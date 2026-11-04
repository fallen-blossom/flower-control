"""Run the offline recipe with a scoped environment and retain build evidence."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from prepare import capacity, digest


def inventory(directory, *, exclude_git=False):
    return {path.relative_to(directory).as_posix():digest(path) for path in sorted(directory.rglob('*'))
        if path.is_file() and (not exclude_git or '.git' not in path.relative_to(directory).parts)}


def build(lock_path, jobs, *, work_root=None, msys_root=None):
    lock=json.loads(lock_path.read_bytes());work=Path(work_root or lock['work_root'])
    capacity(work,required=1024**3)
    for row in lock['packages']+[s for s in lock['sources'] if s['kind']=='archive']:
        name=row.get('filename') or row['url'].rsplit('/',1)[-1]
        if digest(work/'downloads'/name)!=row['sha256']:raise ValueError('encoder_build_input_changed:'+name)
    x264=next(s for s in lock['sources'] if s['kind']=='git')
    if digest(work/'downloads'/('x264-'+x264['commit']+'.tar'))!=x264['canonical_git_archive_sha256']:
        raise ValueError('encoder_build_x264_input_changed')
    msys=Path(msys_root or lock['existing_msys_root'])
    windows=Path(os.environ['SystemRoot'])
    env={key:os.environ[key] for key in ('SystemRoot','WINDIR','COMSPEC','SystemDrive') if key in os.environ}
    env.update(PATH=';'.join(map(str,(work/'toolchain/ucrt64/bin',work/'toolchain/usr/bin',msys/'usr/bin',windows/'System32'))),
        TEMP=str(work/'tmp'),TMP=str(work/'tmp'),MSYSTEM='UCRT64',MSYS2_PATH_TYPE='strict',
        GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='NUL',GIT_TERMINAL_PROMPT='0',
        LC_ALL='C',LANG='C',TZ='UTC')
    recipe=Path(__file__).with_name('build.sh')
    copied=work/'build-recipe.sh'
    if copied.exists():
        if digest(copied)!=digest(recipe):raise ValueError('encoder_existing_recipe_changed_new_workspace_required')
    else:shutil.copyfile(recipe,copied)
    evidence=dict(schema=1,input_lock_sha256=digest(lock_path),recipe_sha256=digest(copied),
        source_hashes=inventory(work/'sources',exclude_git=True),
        compiler_packages=[{key:r[key] for key in ('name','version','filename','sha256','url','checksum_source')} for r in lock['packages']],
        shell=dict(path=str(msys/'usr/bin/bash.exe'),sha256=digest(msys/'usr/bin/bash.exe')),
        jobs=jobs,network_enabled=False,installed_encoder_changed=False)
    (work/'build-evidence.started.json').write_text(json.dumps(evidence,indent=2)+'\n')
    started=time.monotonic()
    with (work/'logs/build.stdout.log').open('wb') as stdout,(work/'logs/build.stderr.log').open('wb') as stderr:
        result=subprocess.run([str(msys/'usr/bin/bash.exe'),'--noprofile','--norc',str(copied).replace('\\','/'),str(work),str(jobs)],
            cwd=work,env=env,stdout=stdout,stderr=stderr,creationflags=subprocess.CREATE_NO_WINDOW)
    evidence.update(exit_code=result.returncode,elapsed_seconds=round(time.monotonic()-started,3),
        sources_unchanged=evidence['source_hashes']==inventory(work/'sources',exclude_git=True),
        output_hashes=inventory(work/'output'))
    (work/'build-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
    if result.returncode:raise RuntimeError('encoder_build_failed:'+str(work/'logs/build.stderr.log'))
    return evidence


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock',type=Path,required=True)
    parser.add_argument('--jobs',type=int,default=4)
    parser.add_argument('--work-root',type=Path)
    parser.add_argument('--msys-root',type=Path)
    args=parser.parse_args()
    if not 1<=args.jobs<=8:parser.error('jobs must be between 1 and 8')
    result=build(args.lock,args.jobs,work_root=args.work_root,msys_root=args.msys_root)
    print(json.dumps({key:result[key] for key in ('exit_code','elapsed_seconds','sources_unchanged','output_hashes')},indent=2))
