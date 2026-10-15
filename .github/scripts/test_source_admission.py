import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from source_admission import tag_version, admit


class SourceAdmissionTests(unittest.TestCase):
    def test_version_tags_bind_manifest_and_reject_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'release.json').write_text('{"version":"0.1.0"}')
            self.assertEqual(tag_version(root,{'versionFile':'release.json'},'v0.1.0'),'0.1.0')
            for tag in ['v0.2.0','v01.1.0','main']:
                with self.assertRaises(ValueError):tag_version(root,{'versionFile':'release.json'},tag)
            with self.assertRaises(ValueError):tag_version(root,{'versionFile':'../release.json'},'v0.1.0')

    def test_foreign_owner_stops_before_git_or_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'Cargo.toml').write_text('[package]\nversion="0.1.0"\n')
            contract={'repository':'owned/repo','versionFile':'Cargo.toml'}
            env={'GITHUB_REF_NAME':'v0.1.0','GITHUB_SHA':'a'*40,'GITHUB_REF_TYPE':'tag','GITHUB_REPOSITORY':'fork/repo'}
            with patch('source_admission.subprocess.run') as run:
                with self.assertRaises(ValueError):admit(root,contract,env)
                run.assert_not_called()


if __name__=='__main__':unittest.main()
