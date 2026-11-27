from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def tracked_files():
    try:
        output = subprocess.check_output(["git", "ls-files"], cwd=str(ROOT), stderr=subprocess.DEVNULL)
        names = [line for line in output.decode("utf-8").splitlines() if line]
        if names:
            return [ROOT / name for name in names]
    except (OSError, subprocess.CalledProcessError):
        pass
    ignored_parts = {".git", "build", "dist", "__pycache__", ".pytest_cache"}
    return [
        path for path in ROOT.rglob("*")
        if path.is_file() and not any(part in ignored_parts or part.endswith(".egg-info") for part in path.parts)
    ]


FILES = tracked_files()
TEXT_FILES = [path for path in FILES if path.suffix not in (".png", ".jpg", ".jpeg", ".gif", ".webp")]


class RepositoryHygieneTest(unittest.TestCase):
    def test_py_typed_marker_exists(self):
        self.assertTrue((ROOT / "src" / "pyfilecage" / "py.typed").is_file())

    def test_no_tracked_pycache_directories(self):
        self.assertEqual([str(path) for path in FILES if "__pycache__" in path.parts], [])

    def test_no_tracked_pyc_or_pyo_files(self):
        self.assertEqual([str(path) for path in FILES if path.suffix in (".pyc", ".pyo")], [])

    def test_no_build_or_dist_outputs_present_as_source_files(self):
        self.assertEqual([str(path) for path in FILES if "build" in path.parts or "dist" in path.parts], [])

    def test_no_egg_info_outputs_present_as_source_files(self):
        self.assertEqual([str(path) for path in FILES if any(part.endswith(".egg-info") for part in path.parts)], [])

    def test_no_macos_metadata_files(self):
        self.assertEqual([str(path) for path in FILES if path.name == ".DS_Store"], [])

    def test_no_local_user_paths_in_source_files(self):
        offenders = []
        for path in TEXT_FILES:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if ("/" + "Users" + "/") in text or ("/" + "home" + "/") in text or ("\\" + "Users" + "\\") in text:
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])

    def test_no_private_gmail_or_coauthor_markers_in_source_files(self):
        offenders = []
        for path in TEXT_FILES:
            try:
                text = path.read_text(encoding="utf-8").lower()
            except UnicodeDecodeError:
                continue
            if ("@" + "gmail.com") in text or ("co-" + "authored-by") in text:
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])

    def test_no_secret_assignment_literals_in_source_files(self):
        offenders = []
        markers = ("pypi" + "_token", "api" + "_key" + " =", "secret" + "_key" + " =", "pass" + "word" + " =", "-----begin " + "private" + " key-----")
        for path in TEXT_FILES:
            try:
                text = path.read_text(encoding="utf-8").lower()
            except UnicodeDecodeError:
                continue
            if any(marker in text for marker in markers):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])


class PackagingMetadataHygieneTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import tomllib
        except ImportError:
            tomllib = None
        cls.tomllib = tomllib

    def parse_pyproject(self):
        if self.tomllib is not None:
            return self.tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        data = {}
        current = data
        for raw in (ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                current = data
                for part in line.strip("[]").split("."):
                    current = current.setdefault(part, {})
            elif "=" in line:
                key, value = line.split("=", 1)
                current[key.strip()] = value.strip()
        return data

    def test_project_name_version_and_python_floor(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('name = "pyfilecage"', text)
        self.assertIn('version = "1.0.0"', text)
        self.assertIn('requires-python = ">=3.9"', text)

    def test_zero_runtime_dependencies(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("dependencies = []", text)

    def test_console_script_entry_point(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('pyfilecage = "pyfilecage.cli:main"', text)

    def test_src_layout_and_package_data_configured(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('package-dir = { "" = "src" }', text)
        self.assertIn('pyfilecage = ["py.typed"]', text)
        self.assertIn('exclude = ["tests*"]', text)

    def test_license_file_present(self):
        self.assertIn("MIT License", (ROOT / "LICENSE").read_text(encoding="utf-8"))

    def test_manifest_includes_project_docs_and_marker(self):
        text = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn("README.md", text)
        self.assertIn("LICENSE", text)
        self.assertIn("py.typed", text)


class WorkflowHygieneTest(unittest.TestCase):
    def test_publish_uses_oidc_and_not_static_token(self):
        text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("id-token: write", text)
        self.assertIn("name: pypi", text)
        self.assertIn("pypa/gh-action-pypi-publish@release/v1", text)
        self.assertNotIn("PYPI" + "_TOKEN", text)
        self.assertNotIn("password:", text)

    def test_publish_uses_ubuntu_2404(self):
        text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("ubuntu-24.04", text)

    def test_ci_matrix_covers_python_39_through_313(self):
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn(version, text)
        self.assertIn("ubuntu-24.04", text)

    def test_ci_checks_wheel_hygiene(self):
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("pyfilecage/py.typed", text)
        self.assertIn("__pycache__", text)
        self.assertIn("tests/", text)

    def test_required_repository_docs_exist(self):
        for relative in (
            "README.md", "CONTRIBUTING.md", "SECURITY.md", "docs/GOOD_FIRST_ISSUES.md",
            ".github/PULL_REQUEST_TEMPLATE.md", ".github/ISSUE_TEMPLATE/bug_report.yml",
            ".github/ISSUE_TEMPLATE/feature_request.yml", ".github/ISSUE_TEMPLATE/config.yml",
        ):
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_good_first_issues_has_ten_specs(self):
        text = (ROOT / "docs" / "GOOD_FIRST_ISSUES.md").read_text(encoding="utf-8")
        count = sum(1 for line in text.splitlines() if len(line) > 3 and line[0].isdigit() and ". **" in line)
        self.assertGreaterEqual(count, 10)


if __name__ == "__main__":
    unittest.main()
