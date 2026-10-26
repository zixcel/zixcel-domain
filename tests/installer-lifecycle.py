#!/usr/bin/env python3
"""Offline installer acceptance using an explicitly selected released zix and cached releases.
Usage: installer-lifecycle.py /official/package/zix OLD_VERSION OLD_CACHE NEW_VERSION NEW_CACHE
Each cache contains the official archive and SHA256SUMS. No live provider access.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

cli = Path(sys.argv[1]).resolve(strict=True)
old_version, old_cache, new_version, new_cache = sys.argv[2:]
caches = {old_version: str(Path(old_cache).resolve()), new_version: str(Path(new_cache).resolve())}
installer = Path(__file__).resolve().parents[1] / "playground/install-native-local.sh"
assert cli.name == "zix"
release = json.loads((cli.parent / "RELEASE.json").read_text())
assert release["package"] == "zix-cli"
assert tuple(map(int, release["version"].split("."))) >= (0, 2, 5)
with tempfile.TemporaryDirectory(prefix="domain-installer-acceptance-") as name:
    root = Path(name)
    root.chmod(0o700)
    binaries = root / "bin"
    binaries.mkdir(mode=0o700)
    (binaries / "zix").symlink_to(cli)
    fake = binaries / "gh"
    fake.write_text("#!/usr/bin/python3\nimport os,pathlib,shutil,sys\n"
                    + "caches=" + repr(caches) + "\n"
                    + "a=sys.argv[1:];v=a[a.index('download')+1].rsplit('/',1)[-1][1:]\n"
                    + "d=pathlib.Path(a[a.index('--dir')+1]);s=pathlib.Path(caches[v])\n"
                    + "for p in s.iterdir():\n"
                    + " if p.is_file() and (p.name=='SHA256SUMS' or p.name.endswith('.tar.gz')):\n"
                    + "  shutil.copyfile(p,d/p.name)\n"
                    + "  if os.environ.get('CORRUPT_FIXTURE') and p.name.endswith('.tar.gz'):\n"
                    + "   with (d/p.name).open('ab') as f:f.write(b'corrupt')\n")
    fake.chmod(0o700)
    env = {"HOME": str(Path.home()), "PATH": str(binaries) + ":/usr/bin:/bin",
           "XDG_CONFIG_HOME": str(root / "config"), "XDG_DATA_HOME": str(root / "data")}
    def run(args, environment=None):
        return subprocess.run(args, env=environment or env, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=30)
    def install(version):
        result = run(["bash", str(installer), version])
        assert result.returncode == 0, result.stderr
    def command(*args):
        result = run([str(cli), *args])
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    def state():
        return command("extensions", "inspect", "domain", "--format", "json")["entry"]
    install(old_version)
    command("extensions", "disable", "domain")
    install(new_version)
    assert state()["version"] == new_version and not state()["enabled"]
    install(old_version)
    assert state()["version"] == old_version and not state()["enabled"]
    install(new_version)
    command("extensions", "enable", "domain")
    assert state()["enabled"]
    registry = root / "config/zix/extensions.json"
    previous = registry.read_bytes()
    corrupt = run(["bash", str(installer), new_version], dict(env, CORRUPT_FIXTURE="1"))
    assert corrupt.returncode != 0 and registry.read_bytes() == previous
    print(json.dumps({"fresh_install": True, "disabled_upgrade_preserved": True,
                      "explicit_rollback": True, "enable": True,
                      "bad_archive_preserves_registration": True,
                      "official_cli_version": release["version"], "provider_credentials_used": False}))
