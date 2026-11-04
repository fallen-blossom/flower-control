"""Collect the actual minimal encoder sources, recipes, notices and evidence."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

from prepare import capacity, digest, verified_copy


def package(lock_path, verification_path, *, work_root=None, msys_root=None, output_dir=None):
    lock=json.loads(lock_path.read_bytes());work=Path(work_root or lock['work_root'])
    evidence=json.loads((work/'build-evidence.json').read_bytes())
    verification=json.loads(verification_path.read_bytes())
    if evidence.get('exit_code')!=0 or evidence.get('sources_unchanged') is not True or verification.get('passed') is not True:
        raise ValueError('encoder_verified_unmodified_sources_required')
    capacity(work,required=256*1024**2)
    built=work/'output'
    binaries={name:digest(built/name) for name in ('ffmpeg.exe','ffprobe.exe')}
    if any(evidence['output_hashes'].get(name)!=sha for name,sha in binaries.items()):
        raise ValueError('encoder_output_changed_after_build')
    if verification.get('encoder_sha256')!=binaries['ffmpeg.exe'] or verification.get('probe_sha256')!=binaries['ffprobe.exe']:
        raise ValueError('encoder_verification_does_not_bind_output')
    output=Path(output_dir) if output_dir is not None else built
    if output_dir is not None:
        output.mkdir(parents=True,exist_ok=False)
        capacity(output,required=256*1024**2)
        for name,sha in binaries.items():verified_copy(built/name,output/name,sha)
    import_logs=output/'inspection' if output_dir is not None else work/'logs'
    import_logs.mkdir(exist_ok=True)
    env={**os.environ,'PATH':str(work/'toolchain/ucrt64/bin')+';'+os.environ['SystemRoot']+'/System32',
        'TEMP':str(work/'tmp'),'TMP':str(work/'tmp')}
    imports={}
    system={'kernel32.dll','msvcrt.dll','ucrtbase.dll','advapi32.dll','bcrypt.dll','ole32.dll',
        'user32.dll','shell32.dll','ws2_32.dll','ntdll.dll','secur32.dll','synchronization.dll'}
    for name in binaries:
        result=subprocess.run([str(work/'toolchain/ucrt64/bin/objdump.exe'),'-p',str(output/name)],
            capture_output=True,text=True,env=env,creationflags=subprocess.CREATE_NO_WINDOW,check=True)
        names=sorted(set(re.findall(r'DLL Name:\s*(\S+)',result.stdout)))
        if not names or any(n.lower() not in system and not n.lower().startswith('api-ms-win-') for n in names):
            raise ValueError('encoder_non_system_runtime_dependency:'+str(names))
        imports[name]=names
        (import_logs/(name+'.imports.txt')).write_text(result.stdout,encoding='utf-8')
    stage=output/'corresponding-source' if output_dir is not None else work/'corresponding-source'
    stage.mkdir(exist_ok=False)
    files={}
    replacements=[]
    for path,label in ((work,'${WORK}'),(Path(msys_root or lock['existing_msys_root']),'${MSYS_ROOT}')):
        variants={str(path),path.as_posix(),json.dumps(str(path))[1:-1]}
        if path.drive:
            variants.add('/'+path.drive[0].lower()+path.as_posix()[2:])
        replacements.extend((value.encode(),label.encode()) for value in variants)
    def add(source,relative,*,public_evidence=False):
        source=Path(source);destination=stage/relative
        destination.parent.mkdir(parents=True,exist_ok=True)
        data=source.read_bytes()
        if public_evidence:
            for before,after in replacements:data=data.replace(before,after)
        destination.write_bytes(data)
        files[relative]=dict(sha256=digest(destination),bytes=destination.stat().st_size)
        if public_evidence:
            files[relative].update(development_original_sha256=digest(source),local_root_tokens_replaced=True)
    archives=[]
    for row in lock['sources']:
        name=('x264-'+row['commit']+'.tar') if row['kind']=='git' else row['url'].rsplit('/',1)[-1]
        expected=row.get('sha256') or row['canonical_git_archive_sha256']
        source=work/'downloads'/name
        if digest(source)!=expected:raise ValueError('encoder_source_archive_changed:'+name)
        add(source,'sources/'+name)
        archives.append(dict(row,archive='sources/'+name,archive_sha256=expected))
    here=Path(__file__).parent
    for name in ('README.md','prepare.py','build.py','build.sh','verify_encoder.py','package_sources.py','test_prepare.py'):
        add(here/name,'recipes/'+name)
    add(work/'build-recipe.sh','evidence/executed-build-recipe.sh')
    for relative in ('ffmpeg-8.1.1/COPYING.GPLv2','ffmpeg-8.1.1/COPYING.GPLv3',
        'ffmpeg-8.1.1/COPYING.LGPLv2.1','ffmpeg-8.1.1/COPYING.LGPLv3','ffmpeg-8.1.1/LICENSE.md',
        'x264/COPYING','zlib-1.3.2/LICENSE'):
        add(work/'sources'/relative,'licenses/'+relative)
    # Preserve the notices of the compiler/runtime environment separately.
    # These labels do not assert that every build tool is incorporated code.
    for family in ('crt','headers','libgcc','gcc','winpthreads','libwinpthread','nasm'):
        directory=work/'toolchain/ucrt64/share/licenses'/family
        for source in sorted(directory.rglob('*')):
            if source.is_file():add(source,'licenses/build-environment/'+family+'/'+source.relative_to(directory).as_posix())
    for relative in ('build-evidence.json','build-evidence.started.json','logs/build.stdout.log','logs/build.stderr.log'):
        add(work/relative,'evidence/'+Path(relative).name,public_evidence=True)
    for component,paths in {
        'ffmpeg':('config.h','config_components.h','ffbuild/config.mak','ffbuild/config.log'),
        'x264':('config.h','config.mak','x264_config.h','x264.pc','config.log'),
        'zlib':('Makefile','zconf.h','zlib.pc'),
    }.items():
        for relative in paths:
            source=work/'build'/component/relative
            if source.is_file():add(source,'evidence/configuration/'+component+'/'+relative,public_evidence=True)
    add(verification_path,'evidence/recording-verification.json')
    public_lock={key:value for key,value in lock.items() if key not in ('work_root','existing_msys_root')}
    (stage/'inputs.lock.json').write_text(json.dumps(public_lock,indent=2)+'\n',encoding='utf-8')
    readme='''# Minimal FFmpeg recording encoder corresponding source

The three upstream source archives are complete, unmodified source inputs for
this build: FFmpeg 8.1.1, the recorded x264 commit, and zlib 1.3.2. No upstream
source patch was applied. The narrow component choices are recorded in the
executed recipe and generated configurations. `source-index.json` pins bytes.

On Windows, use Python 3.14 or later (built-in .tar.zst extraction), obtain an
official MSYS2 shell and the official compiler/assembler
packages listed in `inputs.lock.json`. Place the verified package archives and
these three source archives together in a local inputs directory. The compiler
is a build prerequisite, not included in the encoder binary distribution.

In a new build directory, from this package's recipes directory:

    python prepare.py --offline --lock ../inputs.lock.json --work-root D:/encoder-build --inputs-dir D:/verified-inputs
    python build.py --lock ../inputs.lock.json --work-root D:/encoder-build --msys-root D:/msys64 --jobs 4
    python verify_encoder.py --encoder D:/encoder-build/output/ffmpeg.exe --probe D:/encoder-build/output/ffprobe.exe --output D:/encoder-build/check

The offline preparation path never downloads or invokes a package installer.
Verify package hashes before execution; never replace those inputs with a
similarly named package. The separate controlled-download helper in prepare.py
is specific to the development control plane; other builders can obtain the
fixed inputs directly from the official URLs and verify the recorded hashes.

`licenses/` retains the component texts; compiler/runtime-environment notices
are separated under `licenses/build-environment/`. The general-purpose compiler
and Windows system libraries are not bundled here. The toolchain/runtime
exception texts and exact package manifest are retained for review. Synthetic
recording/probe/decode evidence does not establish foreground recording, host
trust, installed-plugin acceptance or universal legal compliance.
'''
    (stage/'README.md').write_text(readme,encoding='utf-8')
    index=dict(schema=1,encoder_version='8.1.1-flower-minimal-1',binary_hashes=binaries,
        source_archives=archives,source_patches=[],upstream_sources_unchanged=True,
        public_input_lock_sha256=digest(stage/'inputs.lock.json'),
        recipe_sha256=evidence['recipe_sha256'],compiler_packages=evidence['compiler_packages'],
        toolchain_runtime_and_system_link_names=sorted(set(re.findall(r'\s-l([A-Za-z0-9_+.-]+)',
            (work/'build/ffmpeg/ffbuild/config.mak').read_text()))),
        runtime_imports=imports,network_protocols=verification['protocols'],
        public_evidence_uses_portable_root_tokens=True,
        recording_verification_scope=verification['scope'],
        size_limit_behavior_verified=verification.get('size_limit_behavior_verified',False),
        verification_passed=True,public_distribution_requires_matching_source_asset=True,
        global_gpl_compliance_assertion=False)
    (stage/'source-index.json').write_text(json.dumps(index,indent=2)+'\n',encoding='utf-8')
    for name in ('README.md','inputs.lock.json','source-index.json'):
        files[name]=dict(sha256=digest(stage/name),bytes=(stage/name).stat().st_size)
    (stage/'FILES.sha256.json').write_text(json.dumps(files,indent=2)+'\n',encoding='utf-8')
    archive=output/'flower-ffmpeg-8.1.1-minimal-1-corresponding-source.zip'
    with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as bundle:
        for path in sorted(stage.rglob('*')):
            if path.is_file():bundle.write(path,path.relative_to(stage).as_posix())
    shutil.copyfile(work/'sources/ffmpeg-8.1.1/COPYING.GPLv3',output/'LICENSE')
    notice=f'''FFmpeg 8.1.1-flower-minimal-1 — Windows x64 local recording encoder
Copyright (c) 2000-2026 the FFmpeg developers.
FFmpeg and the enabled x264 GPL code are distributed under GPL version 3 or later;
zlib retains its own license and notice. See LICENSE and the source package.

This independent build replaces no installed program automatically. It enables
only the recorded local PNG/concat/pad/H264/MP4 path and required decode checks.
Networking and automatic external dependency detection are disabled.

ffmpeg.exe SHA256: {binaries['ffmpeg.exe']}
Complete build-source materials for this artifact:
  {archive.name}
  SHA256: {digest(archive)}
Provide that actual source package next to the binary at the distribution point,
with equally accessible copying facilities and no additional charge. Its README,
source-index, recipes, configurations and preserved license texts describe the
exact inputs. Do not publish the binary without the matching source asset.

The encoder is a separate process. No affiliation or endorsement by FFmpeg,
VideoLAN, MSYS2 or Gyan Doshi is claimed. Synthetic verification and collected
source materials are not a blanket claim of legal or installed-product acceptance.
'''
    notice+='\nx264: Copyright (C) 2003-2025 x264 project; GPL version 2 or later, combined here under GPLv3 or later.\n'
    notice+='zlib: Copyright (C) 1995-2026 Jean-loup Gailly and Mark Adler.\n'
    texts=[('x264 COPYING',work/'sources/x264/COPYING'),('zlib LICENSE',work/'sources/zlib-1.3.2/LICENSE')]
    for family in ('crt','headers','libgcc'):
        directory=work/'toolchain/ucrt64/share/licenses'/family
        texts.extend(('MinGW/GCC runtime notice: '+family+'/'+source.relative_to(directory).as_posix(),source)
            for source in sorted(directory.rglob('*')) if source.is_file())
    data=notice.encode('utf-8')
    for label,source in texts:data+=('\n\n----- '+label+' (unmodified text) -----\n').encode()+source.read_bytes()
    (output/'NOTICE.txt').write_bytes(data)
    (output/'SOURCE-INDEX.json').write_text(json.dumps(index,indent=2)+'\n',encoding='utf-8')
    return dict(output_directory=str(output),binary_hashes=binaries,source_package=str(archive),
        source_package_sha256=digest(archive),source_package_bytes=archive.stat().st_size,
        source_archive_count=len(archives),runtime_imports=imports)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock',type=Path,required=True)
    parser.add_argument('--verification',type=Path,required=True)
    parser.add_argument('--work-root',type=Path)
    parser.add_argument('--msys-root',type=Path)
    parser.add_argument('--output-dir',type=Path,help='New delivery directory; preserves earlier materials and evidence.')
    args=parser.parse_args()
    print(json.dumps(package(args.lock,args.verification,work_root=args.work_root,msys_root=args.msys_root,
        output_dir=args.output_dir),indent=2))
