"""Verify local fixed inputs; optionally use an explicitly supplied download adapter."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
from urllib.parse import urlsplit, unquote

FREE = 10*1024**3


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def capacity(*paths, required=0):
    for path in paths:
        if shutil.disk_usage(path).free < FREE+required:
            raise RuntimeError('encoder_build_disk_reserve_required:'+str(path))


def run(command, work, name, *, env=None):
    log = work/'logs'/(name+'.log')
    attempt=1
    while log.exists():
        attempt+=1
        log=work/'logs'/(name+'.attempt'+str(attempt)+'.log')
    result = subprocess.run([str(part) for part in command], capture_output=True, env=env,
        creationflags=subprocess.CREATE_NO_WINDOW)
    log.write_bytes(result.stdout+result.stderr)
    if result.returncode:
        raise RuntimeError(name+'_failed:'+str(log))
    return result.stdout.decode('utf-8-sig', errors='strict')


def verified_copy(source, target, expected):
    if digest(source) != expected:
        raise ValueError('encoder_input_digest_mismatch:'+str(source))
    if target.exists():
        if digest(target) != expected:
            raise ValueError('encoder_existing_input_changed:'+str(target))
        return
    with source.open('rb') as src, target.open('xb') as dst:
        shutil.copyfileobj(src, dst)
    if digest(target) != expected:
        raise ValueError('encoder_copied_input_changed:'+str(target))


def fetch(entry, work, *, env, offline=False, inputs_dir=None, control_plane_tools=None,
          control_python=None, staging_root=None, package_cache=None):
    filename = entry.get('filename') or entry['url'].rsplit('/',1)[-1]
    destination = work/'downloads'/filename
    expected = entry['sha256']
    capacity(work, *([staging_root] if staging_root is not None and staging_root.exists() else []), required=256*1024**2)
    if destination.is_file():
        if digest(destination) != expected:
            raise ValueError('encoder_existing_input_changed')
        return destination
    if inputs_dir is not None:
        for candidate in (inputs_dir/filename,inputs_dir/unquote(filename)):
            if candidate.is_file():
                verified_copy(candidate,destination,expected)
                return destination
    if offline or control_plane_tools is None or staging_root is None:
        raise FileNotFoundError('encoder_offline_input_required:'+filename)
    cached = package_cache/filename if package_cache is not None else None
    if cached is not None and cached.is_file() and digest(cached) == expected:
        verified_copy(cached,destination,expected)
        return destination
    stage = staging_root/('flower-encoder-'+work.name)
    stage.mkdir(parents=True,exist_ok=True)
    part = stage/(filename+'.part')
    promoted = stage/filename
    if not promoted.exists():
        host = urlsplit(entry['url']).hostname
        allowed = ['release-assets.githubusercontent.com'] if host=='github.com' else [host]
        command = [control_python or Path(sys.executable), control_plane_tools/'source_assessment.py', 'official-url',
            '--source',entry['url'],'--destination',part,'--checksum','sha256:'+expected,
            '--checksum-source',entry['checksum_source'],'--ttl-minutes','240']
        for item in allowed: command.extend(['--allowed-final-host',item])
        run(command,work,'preflight-'+filename,env=env)
        run([control_python or Path(sys.executable),control_plane_tools/'safe_download.py','download','--source',entry['url'],
            '--destination',part],work,'download-'+filename,env=env)
    verified_copy(promoted,destination,expected)
    return destination


def extract(archive, target):
    if target.exists():
        raise FileExistsError('encoder_extraction_requires_new_directory:'+str(target))
    target.mkdir(parents=True)
    capacity(target,required=1024**3)
    with tarfile.open(archive,'r:*') as stream:
        members=stream.getmembers()
        if len(members)>100000 or sum(member.size for member in members)>2*1024**3:
            raise ValueError('encoder_archive_size_rejected')
        for member in members:
            name=PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or '\\' in member.name or ':' in member.name:
                raise ValueError('encoder_archive_path_rejected')
            if member.issym() or not (member.isfile() or member.isdir() or member.islnk()):
                raise ValueError('encoder_archive_entry_rejected')
        stream.extractall(target,members=members,filter='data')


def merge(source, target):
    for path in sorted(source.rglob('*')):
        if path.is_symlink():
            raise ValueError('encoder_toolchain_link_rejected')
        destination=target/path.relative_to(source)
        if path.is_dir():
            destination.mkdir(parents=True,exist_ok=True)
        else:
            destination.parent.mkdir(parents=True,exist_ok=True)
            verified_copy(path,destination,digest(path))


def prepare(lock_path, *, work_root=None, offline=False, inputs_dir=None, control_plane_tools=None,
            control_python=None, staging_root=None, package_cache=None):
    lock=json.loads(lock_path.read_bytes())
    work=Path(work_root or lock['work_root'])
    if not work.is_absolute() or work==Path(work.anchor):
        raise ValueError('encoder_build_explicit_workspace_required')
    work.mkdir(parents=True,exist_ok=True)
    for name in ('downloads','sources','build','prefix','output','tmp','logs'):
        (work/name).mkdir(exist_ok=True)
    env={**os.environ,'TEMP':str(work/'tmp'),'TMP':str(work/'tmp')}
    capacity(work,*([staging_root] if staging_root is not None and staging_root.exists() else []))
    for entry in lock['packages']+[row for row in lock['sources'] if row['kind']=='archive']:
        archive=fetch(entry,work,env=env,offline=offline,inputs_dir=inputs_dir,
            control_plane_tools=control_plane_tools,control_python=control_python,staging_root=staging_root,
            package_cache=package_cache)
        marker=work/'logs'/('extracted-'+archive.name+'.json')
        if marker.exists():
            continue
        package=entry in lock['packages']
        destination=work/'package-inputs'/archive.name if package else work/'source-inputs'/archive.name
        extract(archive,destination)
        if package:
            for directory in ('ucrt64','usr'):
                if (destination/directory).is_dir():merge(destination/directory,work/'toolchain'/directory)
        else:merge(destination,work/'sources')
        marker.write_text(json.dumps(dict(sha256=digest(archive),destination=str(destination)))+'\n')
        print('prepared '+archive.name,flush=True)
    for entry in [row for row in lock['sources'] if row['kind']=='git']:
        archive_name='x264-'+entry['commit']+'.tar'
        archive=work/'downloads'/archive_name
        if not archive.exists() and inputs_dir is not None and (inputs_dir/archive_name).exists():
            verified_copy(inputs_dir/archive_name,archive,entry['canonical_git_archive_sha256'])
        if not archive.is_file() or digest(archive)!=entry['canonical_git_archive_sha256']:
            raise ValueError('encoder_verified_git_archive_required:'+archive_name)
        if not (work/'sources/x264').exists():extract(archive,work/'sources/x264')
    return work


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock',type=Path,required=True)
    parser.add_argument('--work-root',type=Path)
    parser.add_argument('--inputs-dir',type=Path)
    parser.add_argument('--offline',action='store_true')
    parser.add_argument('--control-plane-tools',type=Path,help='Optional existing trusted controlled-download tool directory.')
    parser.add_argument('--control-python',type=Path)
    parser.add_argument('--staging-root',type=Path,help='Must also be admitted by that controlled downloader; this does not override its policy.')
    parser.add_argument('--package-cache',type=Path)
    args=parser.parse_args()
    print(prepare(args.lock,work_root=args.work_root,offline=args.offline,inputs_dir=args.inputs_dir,
        control_plane_tools=args.control_plane_tools,control_python=args.control_python,
        staging_root=args.staging_root,package_cache=args.package_cache))
