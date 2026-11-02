# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""The install script never prints a generated test-user password: it writes it to
demo/generated/<user>.password, created mode 0600, and prints only that path.

    python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import os
import stat
import tempfile
import unittest
from pathlib import Path

import configure_iya_sts

SOURCE = Path(configure_iya_sts.__file__).read_text(encoding="utf-8")


class PasswordFileTests(unittest.TestCase):
    def test_the_password_file_is_named_for_the_user_beside_the_configuration(self):
        directory = Path("demo") / "generated"
        self.assertEqual(configure_iya_sts.generated_file(directory, "demo-user"),
                         directory / "demo-user.password")
        for bad in ("", ".", "..", "a/b", "a\\b"):
            with self.assertRaises(ValueError):
                configure_iya_sts.generated_file(directory, bad)

    def test_the_password_file_is_created_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            saved = configure_iya_sts.generated_file(Path(tmp) / "generated", "demo-user")
            configure_iya_sts.write_private(saved, "s3cret")
            self.assertEqual(stat.S_IMODE(os.stat(saved).st_mode), 0o600)
            self.assertEqual(saved.read_text(encoding="utf-8"), "s3cret\n")

    def test_an_existing_file_is_narrowed_to_0600_and_rewritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            saved = Path(tmp) / "demo-user.password"
            saved.write_text("old\n", encoding="utf-8")
            os.chmod(saved, 0o644)
            configure_iya_sts.write_private(saved, "new")
            self.assertEqual(stat.S_IMODE(os.stat(saved).st_mode), 0o600)
            self.assertEqual(saved.read_text(encoding="utf-8"), "new\n")

    def test_no_line_prints_a_generated_password(self):
        for line in SOURCE.splitlines():
            if "print(" in line:
                self.assertNotIn("['password']", line)
                self.assertNotIn('["password"]', line)


if __name__ == "__main__":
    unittest.main()
