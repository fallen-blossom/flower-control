"""Exercise the same local PNG/concat/pad/H264/MP4 timeline as Flower."""
from __future__ import annotations
import argparse
import binascii
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib

FILE_SIZE_LIMIT_BYTES=50_000_000


def png(path, width, height, color):
    def chunk(kind,data):
        return struct.pack('>I',len(data))+kind+data+struct.pack('>I',binascii.crc32(kind+data)&0xffffffff)
    rows=b''.join(b'\0'+bytes(color)*width for _ in range(height))
    path.write_bytes(b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,2,0,0,0))
        +chunk(b'IDAT',zlib.compress(rows))+chunk(b'IEND',b''))


def run(args, directory):
    result=subprocess.run([str(p) for p in args],cwd=directory,capture_output=True,timeout=60,
        creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise RuntimeError('encoder_verification_command_failed:'+result.stderr.decode('utf-8',errors='replace'))
    return result.stdout.decode('utf-8',errors='strict')


def encode(encoder,probe,directory):
    directory.mkdir(parents=True,exist_ok=False)
    durations=[.123,.234,.345];colors=[(255,0,0),(0,255,0),(0,0,255)]
    for number,color in enumerate(colors):png(directory/('frame%03d.png'%number),23,17,color)
    timeline=[]
    for number,duration in enumerate(durations):
        held=duration-.001 if number==len(durations)-1 else duration
        timeline.extend(("file 'frame%03d.png'"%number,'option framerate 1000','duration %.6f'%held))
    timeline.extend(("file 'frame002.png'",'option framerate 1000'))
    (directory/'frames.ffconcat').write_text('ffconcat version 1.0\n'+'\n'.join(timeline)+'\n',encoding='ascii')
    movie=directory/'recording.mp4';progress=directory/'encode.progress'
    args=[encoder,'-nostdin','-hide_banner','-loglevel','error','-n','-protocol_whitelist','file',
        '-f','concat','-safe','0','-i','frames.ffconcat','-an','-map_metadata','-1',
        '-vf','pad=ceil(iw/2)*2:ceil(ih/2)*2','-c:v','libx264','-preset','veryfast','-crf','18',
        '-pix_fmt','yuv420p','-fps_mode','vfr','-enc_time_base','1:1000','-t',str(sum(durations)),
        '-fs',str(FILE_SIZE_LIMIT_BYTES),'-progress',progress,movie]
    run(args,directory)
    values=dict(line.split('=',1) for line in progress.read_text().splitlines() if '=' in line)
    information=json.loads(run([probe,'-v','error','-count_frames','-show_streams','-show_format',
        '-show_packets','-of','json',movie],directory))
    video=[s for s in information['streams'] if s['codec_type']=='video']
    if (len(video)!=1 or video[0]['codec_name']!='h264' or video[0]['width']!=24 or video[0]['height']!=18
            or values.get('progress')!='end' or int(values.get('frame','0'))<3):
        raise ValueError('encoder_recording_behavior_changed')
    actual_duration=float(information['format']['duration'])
    # The existing recorder preserves presentation timestamps. MP4 format.duration
    # for this very short B-frame fixture differs from its final presentation
    # timestamp even in the admitted reference build; it is not our timeline oracle.
    expected_pts=[0.,.123,.357,.701]
    actual_pts=sorted(float(packet['pts_time']) for packet in information['packets'])
    if len(actual_pts)!=len(expected_pts) or any(abs(a-b)>.0001 for a,b in zip(actual_pts,expected_pts)):
        raise ValueError('encoder_vfr_presentation_timestamps_changed:'+str(actual_pts))
    decoded=directory/'decoded.rgb'
    run([encoder,'-nostdin','-v','error','-i',movie,'-an','-pix_fmt','rgb24',
        '-fps_mode','passthrough','-f','rawvideo',decoded],directory)
    content=decoded.read_bytes();stride=24*18*3
    if len(content)%stride or len(content)<3*stride:raise ValueError('encoder_decode_frames_missing')
    errors=[]
    for number,color in enumerate(colors):
        frame=content[number*stride:(number+1)*stride]
        samples=[frame[(y*24+x)*3:(y*24+x+1)*3] for y in range(8) for x in range(8)]
        means=[sum(sample[c] for sample in samples)/len(samples) for c in range(3)]
        errors.append(max(abs(means[c]-color[c]) for c in range(3)))
    if max(errors)>16:raise ValueError('encoder_decoded_color_changed:'+str(errors))
    return dict(schema=1,passed=True,recording_frames=int(values['frame']),decoded_frames=len(content)//stride,
        dimensions=[24,18],codec='h264',requested_duration=sum(durations),actual_duration=actual_duration,
        presentation_timestamps=actual_pts,decoded_color_max_errors=errors,progress_end=True,
        mp4_sha256=hashlib.sha256(movie.read_bytes()).hexdigest())


def verify(encoder,probe,directory,*,reference_encoder=None):
    result=encode(encoder,probe,directory)
    protocols=run([encoder,'-hide_banner','-protocols'],directory)
    enabled={line.strip() for line in protocols.splitlines()}-{'Supported file protocols:','Input:','Output:',''}
    if not enabled.issubset({'file','pipe'}):raise ValueError('encoder_network_protocols_present:'+str(enabled))
    result.update(protocols=sorted(enabled),encoder_sha256=hashlib.sha256(encoder.read_bytes()).hexdigest(),
        probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),physical_recording_or_foreground_verified=False,
        file_size_limit_bytes=FILE_SIZE_LIMIT_BYTES,size_limit_behavior_verified=False,
        scope='production encoding/timeline options on short synthetic frames; no size-limit/foreground claim')
    if reference_encoder is not None:
        reference=encode(reference_encoder,probe,directory/'reference')
        fields=('recording_frames','decoded_frames','dimensions','codec','requested_duration','actual_duration',
            'presentation_timestamps','progress_end')
        if any(reference[field]!=result[field] for field in fields):
            raise ValueError('encoder_reference_recording_behavior_changed')
        result.update(reference_encoder_sha256=hashlib.sha256(reference_encoder.read_bytes()).hexdigest(),
            reference_behavior_matches=True,reference_result=reference)
    (directory/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--encoder',type=Path,required=True)
    parser.add_argument('--probe',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--reference-encoder',type=Path,help='Optional already-admitted encoder, for the same owned fixture.')
    args=parser.parse_args()
    print(json.dumps(verify(args.encoder.absolute(),args.probe.absolute(),args.output.absolute(),
        reference_encoder=args.reference_encoder.absolute() if args.reference_encoder else None),indent=2))
