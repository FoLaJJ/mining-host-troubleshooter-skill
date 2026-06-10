import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "scripts" / "install-skill.mjs"


class InstallSkillTests(unittest.TestCase):
    def test_default_install_uses_skill_package_directory_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "skills"
            result = subprocess.run(
                ["node", str(INSTALLER), "install", "--dest", str(dest)],
                capture_output=True,
                text=True,
                check=False,
                cwd=str(REPO_ROOT),
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)
            self.assertTrue((dest / "mining-host-troubleshooter-skill" / "SKILL.md").exists())
            self.assertFalse((dest / "mining-host-troubleshooter").exists())

    def test_force_install_removes_legacy_alias_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "skills"
            legacy = dest / "mining-host-troubleshooter"
            legacy.mkdir(parents=True, exist_ok=True)
            (legacy / "legacy.txt").write_text("old", encoding="utf-8")

            result = subprocess.run(
                ["node", str(INSTALLER), "install", "--dest", str(dest), "--force"],
                capture_output=True,
                text=True,
                check=False,
                cwd=str(REPO_ROOT),
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)
            self.assertFalse(legacy.exists())
            self.assertTrue((dest / "mining-host-troubleshooter-skill" / "SKILL.md").exists())

    def test_install_skips_locally_ignored_noise_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "skills"
            result = subprocess.run(
                ["node", str(INSTALLER), "install", "--dest", str(dest), "--force"],
                capture_output=True,
                text=True,
                check=False,
                cwd=str(REPO_ROOT),
            )

            installed = dest / "mining-host-troubleshooter-skill"
            self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)
            self.assertFalse((installed / "gcm-diagnose.log").exists())
            self.assertFalse((installed / "INTERVIEW_PREP.md").exists())


if __name__ == "__main__":
    unittest.main()
