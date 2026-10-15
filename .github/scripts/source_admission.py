"""Version tag admission owned by each binary/image repository (no central checkout)."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import urllib.request


def tag_version(root, contract, tag):
    path = Path(contract['versionFile'])
    if path.is_absolute() or '..' in path.parts or not (root/path).resolve().is_relative_to(root.resolve()):
        raise ValueError('Version manifest must be repository-owned')
    if path.suffix == '.toml':
        version = tomllib.loads((root/path).read_text())['package']['version']
    else:
        version = json.loads((root/path).read_text())['version']
    if not isinstance(version,str) or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',version) or tag != 'v'+version:
        raise ValueError('Tag must match the owning manifest version')
    return version


def admit(root, contract, env):
    version=tag_version(root,contract,env['GITHUB_REF_NAME'])
    sha=env['GITHUB_SHA']
    if env['GITHUB_REPOSITORY']!=contract['repository'] or env['GITHUB_REF_TYPE']!='tag' or not re.fullmatch('[a-f0-9]{40}',sha):
        raise ValueError('Foreign owner or mutable source')
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()!=sha:
        raise ValueError('Checkout source mismatch')
    subprocess.run(['git','merge-base','--is-ancestor',sha,'origin/'+contract['defaultBranch']],cwd=root,check=True)
    request=urllib.request.Request(f"https://api.github.com/repos/{contract['repository']}/actions/runs?head_sha={sha}&per_page=100",
        headers={'Authorization':'Bearer '+env['GH_TOKEN'],'Accept':'application/vnd.github+json','User-Agent':'owner-tag-admission'})
    with urllib.request.urlopen(request,timeout=30) as response:
        runs=json.load(response)['workflow_runs']
    if not contract['requiredWorkflows']:
        raise ValueError('Required CI cannot be empty')
    for name in contract['requiredWorkflows']:
        selected=[r for r in runs if r.get('path','').split('@')[0]=='.github/workflows/'+name and r['event']=='push' and r['head_branch']==contract['defaultBranch']]
        if not selected or selected[0]['status']!='completed' or selected[0]['conclusion']!='success':
            raise ValueError('Exact default-branch source CI has not succeeded')
    return version


if __name__=='__main__':
    version=admit(Path.cwd(),json.loads(Path('.github/tag-release.json').read_text()),os.environ)
    with open(os.environ['GITHUB_OUTPUT'],'a') as output:
        output.write('version='+version+'\n')
