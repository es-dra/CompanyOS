from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parents[1]


class InstallAndWorkflowContractSecurityTests(unittest.TestCase):
    def test_workflow_step_schema_is_closed_and_fully_bound(self) -> None:
        contract = json.loads(
            (
                REPO_ROOT / "runtime/contracts/v1/runtime-contracts.schema.json"
            ).read_text(encoding="utf-8")
        )
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "#/$defs/WorkflowStep",
            "$defs": contract["$defs"],
        }
        validator = Draft202012Validator(schema)
        valid = {
            "step_id": "write-report",
            "adapter": "local",
            "action": "write",
            "resource": "repo://project/report.json",
            "request_digest": "0" * 64,
        }

        validator.validate(valid)
        self.assertTrue(list(validator.iter_errors(valid | {"unexpected": True})))
        self.assertTrue(list(validator.iter_errors({"step_id": "write-report"})))

    @unittest.skipIf(os.name == "nt", "POSIX shell security test")
    def test_posix_installer_rejects_lexical_escape(self) -> None:
        shell = shutil.which("sh")
        if shell is None:
            self.skipTest("sh is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "user"
            company_home = home / ".company-os"
            home.mkdir()
            escaped = home / "escaped"
            raw_install = company_home / ".." / "escaped" / "CompanyOS"
            environment = os.environ | {
                "HOME": str(home),
                "COMPANY_OS_HOME": str(company_home),
            }

            result = subprocess.run(
                [shell, str(REPO_ROOT / "install.sh"), str(raw_install)],
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(escaped.exists())

    @unittest.skipIf(os.name == "nt", "POSIX shell security test")
    def test_posix_installer_rejects_symbolic_link_escape(self) -> None:
        shell = shutil.which("sh")
        if shell is None:
            self.skipTest("sh is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "user"
            company_home = home / ".company-os"
            outside = root / "outside"
            company_home.mkdir(parents=True)
            outside.mkdir()
            link = company_home / "redirect"
            link.symlink_to(outside, target_is_directory=True)
            environment = os.environ | {
                "HOME": str(home),
                "COMPANY_OS_HOME": str(company_home),
            }

            result = subprocess.run(
                [shell, str(REPO_ROOT / "install.sh"), str(link / "CompanyOS")],
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((outside / "CompanyOS").exists())

    @unittest.skipUnless(os.name == "nt", "PowerShell reparse-point security test")
    def test_powershell_installer_rejects_reparse_escape(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("PowerShell is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            company_home = root / "company-home"
            outside = root / "outside"
            redirect = company_home / "redirect"
            company_home.mkdir()
            outside.mkdir()
            quoted_redirect = str(redirect).replace("'", "''")
            quoted_outside = str(outside).replace("'", "''")
            create = subprocess.run(
                [
                    powershell,
                    "-NoProfile",
                    "-Command",
                    f"New-Item -ItemType Junction -Path '{quoted_redirect}' "
                    f"-Target '{quoted_outside}' | Out-Null",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if create.returncode != 0:
                self.skipTest(f"cannot create test junction: {create.stderr.strip()}")
            try:
                result = subprocess.run(
                    [
                        powershell,
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(REPO_ROOT / "install.ps1"),
                        "-InstallRoot",
                        str(redirect / "CompanyOS"),
                        "-Force",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("reparse point", (result.stderr + result.stdout).lower())
                self.assertFalse((outside / "CompanyOS").exists())
            finally:
                quoted_redirect = str(redirect).replace("'", "''")
                subprocess.run(
                    [
                        powershell,
                        "-NoProfile",
                        "-Command",
                        f"Remove-Item -LiteralPath '{quoted_redirect}' -Force",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )


if __name__ == "__main__":
    unittest.main()
