"""Build the local read-only predicate probe with no NuGet package sources."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from tools.prepare_work_authority_update import digest
from tools.runtime_snapshot import reject_links


def validate_probe(folder:Path):
    reject_links(folder)
    proof=json.loads((folder/'probe-build-evidence.json').read_bytes())
    if proof.get('exit_code')!=0 or proof.get('package_sources_cleared') is not True:
        raise ValueError('readonly_probe_build_evidence_required')
    old_sources={'Program.cs','Probe.csproj','NuGet.Config'}
    if set(proof['source_hashes']) not in (old_sources,old_sources|{'Boundary.cs','@installation-location'}):
        raise ValueError('readonly_probe_inventory_changed')
    for name,sha in proof['source_hashes'].items():
        original = ROOT/'flower_control/drivers/high_helper/InstallationLocation.cs' if name == '@installation-location' else ROOT/'tools/codex_signer_probe'/name
        copied = folder/'InstallationLocation.cs' if name == '@installation-location' else folder/name
        reject_links(original); reject_links(copied)
        if digest(original)!=sha or digest(copied)!=sha:
            raise ValueError('readonly_probe_source_changed')
    required={'Probe.exe','Probe.dll','Probe.deps.json','Probe.runtimeconfig.json'}
    binaries=set(proof['binary_hashes'])
    if not required.issubset(binaries) or (binaries != required and 'coreclr.dll' not in binaries):
        raise ValueError('readonly_probe_inventory_changed')
    native=folder/'native';reject_links(native)
    actual={p.name for p in native.iterdir() if p.is_file() and p.suffix.lower() in {'.exe','.dll','.json'}}
    if actual != binaries:
        raise ValueError('readonly_probe_inventory_changed')
    for name,sha in proof['binary_hashes'].items():
        if Path(name).name != name or any(token in name for token in ('\\','/',':','..')) or Path(name).suffix.lower() not in {'.exe','.dll','.json'}:
            raise ValueError('readonly_probe_inventory_changed')
        path=folder/'native'/name;reject_links(path)
        if digest(path)!=sha:raise ValueError('readonly_probe_binary_changed')
    return proof


def prepare(output:Path):
    if output.exists() or not output.absolute().is_relative_to(Path(os.environ['TEMP']).resolve()):
        raise ValueError('new_temp_probe_output_required')
    reject_links(output);output.mkdir(parents=True)
    sources=['Program.cs','Probe.csproj','NuGet.Config']
    if (ROOT/'tools/codex_signer_probe/Boundary.cs').is_file():
        sources.append('Boundary.cs')
    for name in sources:shutil.copyfile(ROOT/'tools/codex_signer_probe'/name,output/name)
    linked=(ROOT/'flower_control/drivers/high_helper/InstallationLocation.cs') if 'Boundary.cs' in sources else None
    if linked is not None:
        shutil.copyfile(linked,output/'InstallationLocation.cs')
    env={**os.environ,'DOTNET_CLI_TELEMETRY_OPTOUT':'1','DOTNET_SKIP_FIRST_TIME_EXPERIENCE':'1'}
    dotnet=Path(os.environ['ProgramFiles'])/'dotnet/dotnet.exe'
    command=[str(dotnet),'build',str(output/'Probe.csproj'),'--nologo','-c','Release','--configfile',str(output/'NuGet.Config'),'-o',str(output/'native'),'/p:NuGetAudit=false']
    if linked is not None: command.append('/p:FlowerInstallationLocationSource='+str(output/'InstallationLocation.cs'))
    result=subprocess.run(command,capture_output=True,env=env,timeout=90,creationflags=subprocess.CREATE_NO_WINDOW)
    (output/'build.stdout.log').write_bytes(result.stdout);(output/'build.stderr.log').write_bytes(result.stderr)
    if result.returncode:raise ValueError('readonly_probe_build_failed')
    source_hashes={name:digest(output/name) for name in sources}
    if linked is not None: source_hashes['@installation-location']=digest(linked)
    proof=dict(schema=1,exit_code=0,package_sources_cleared=True,
               source_hashes=source_hashes,
               binary_hashes={name:digest(output/'native'/name) for name in ['Probe.exe','Probe.dll','Probe.deps.json','Probe.runtimeconfig.json']},
               input_or_authority_operations=False,scope='local original signed Codex predicate via exact protected native DLL')
    (output/'probe-build-evidence.json').write_text(json.dumps(proof,indent=2)+'\n')
    validate_probe(output);return proof


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();proof=prepare(args.output)
    print(json.dumps(dict(output=str(args.output),exit_code=proof['exit_code'],binary_hashes=proof['binary_hashes'])))
