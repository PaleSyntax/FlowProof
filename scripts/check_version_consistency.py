"""Check release-version declarations without importing runtime applications."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]


def _required_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _fastapi_version(path: Path, expected_title: str) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "FastAPI":
            continue
        values = {
            keyword.arg: keyword.value.value
            for keyword in node.keywords
            if keyword.arg in {"title", "version"}
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        }
        if values.get("title") == expected_title:
            return _required_string(values.get("version"), f"{expected_title} FastAPI version")
    raise ValueError(f"FastAPI declaration titled {expected_title!r} was not found in {path}")


def _openapi_info_version(path: Path) -> str:
    info_indent: int | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if info_indent is None:
            if indent == 0 and stripped == "info:":
                info_indent = indent
            continue
        if indent <= info_indent:
            break
        if stripped.startswith("version:"):
            return _required_string(
                stripped.partition(":")[2].strip().strip("\"'"), "OpenAPI info.version"
            )
    raise ValueError(f"OpenAPI info.version was not found in {path}")


def _regex_versions(path: Path, pattern: str, label: str) -> dict[str, str]:
    matches = re.findall(pattern, path.read_text(encoding="utf-8"), flags=re.MULTILINE)
    if not matches:
        raise ValueError(f"{label} version declaration was not found in {path}")
    return {
        f"{label} #{index}": _required_string(match, label)
        for index, match in enumerate(matches, start=1)
    }


def collect_versions(root: Path = ROOT) -> dict[str, str]:
    pyproject = tomllib.loads((root / "backend" / "pyproject.toml").read_text(encoding="utf-8"))
    frontend = json.loads((root / "frontend" / "package.json").read_text(encoding="utf-8"))
    lockfile = json.loads((root / "frontend" / "package-lock.json").read_text(encoding="utf-8"))
    appliance = json.loads(
        (root / "productization" / "windows" / "appliance-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    evidence_schema = json.loads(
        (root / "specs" / "evidence" / "evidence-capsule.schema.json").read_text(
            encoding="utf-8"
        )
    )
    mock_contract = json.loads(
        (root / "specs" / "providers" / "mock-accounting" / "contract.json").read_text(
            encoding="utf-8"
        )
    )
    xero_contract = json.loads(
        (root / "specs" / "providers" / "xero-demo" / "contract.json").read_text(
            encoding="utf-8"
        )
    )
    project = pyproject.get("project")
    packages = lockfile.get("packages")
    if not isinstance(project, dict) or not isinstance(packages, dict):
        raise TypeError("project metadata has an unexpected structure")
    root_package = packages.get("")
    if not isinstance(root_package, dict):
        raise TypeError("package-lock root package metadata is missing")

    versions = {
        "backend project.version": _required_string(
            project.get("version"), "backend project.version"
        ),
        "frontend package.json version": _required_string(
            frontend.get("version"), "frontend package.json version"
        ),
        "frontend package-lock top-level version": _required_string(
            lockfile.get("version"), "frontend package-lock top-level version"
        ),
        "frontend package-lock root package version": _required_string(
            root_package.get("version"), "frontend package-lock root package version"
        ),
        "FlowProof API FastAPI version": _fastapi_version(
            root / "backend" / "src" / "flowproof" / "main_core.py", "FlowProof API"
        ),
        "Mock Accounting FastAPI version": _fastapi_version(
            root / "mock-accounting" / "app" / "main.py", "FlowProof Mock Accounting"
        ),
        "OpenAPI info.version": _openapi_info_version(root / "specs" / "openapi.yaml"),
        "Windows appliance version": _required_string(
            appliance.get("application_version"), "Windows appliance version"
        ),
        "evidence capsule package version": _required_string(
            evidence_schema.get("properties", {}).get("package_version", {}).get("const"),
            "evidence capsule package version",
        ),
        "Mock Accounting adapter package version": _required_string(
            mock_contract.get("adapter_version"), "Mock Accounting adapter version"
        ).partition("-")[0],
        "Xero Demo adapter package version": _required_string(
            xero_contract.get("adapter_version"), "Xero Demo adapter version"
        ).partition("-")[0],
    }
    regex_sources = (
        (
            root / "backend" / "Dockerfile",
            r"^ARG VERSION=(\d+\.\d+\.\d+)$",
            "backend Docker build version",
        ),
        (
            root / "frontend" / "Dockerfile",
            r"^ARG VERSION=(\d+\.\d+\.\d+)$",
            "frontend Docker build version",
        ),
        (
            root / "mock-accounting" / "Dockerfile",
            r"^ARG VERSION=(\d+\.\d+\.\d+)$",
            "mock-accounting Docker build version",
        ),
        (
            root / "docker-compose.production-smoke.yml",
            r'^\s+VERSION:\s+"(\d+\.\d+\.\d+)"$',
            "production-smoke build version",
        ),
        (
            root / ".github" / "workflows" / "container-security.yml",
            r"--build-arg VERSION=(\d+\.\d+\.\d+)",
            "container-security build version",
        ),
        (
            root / ".github" / "workflows" / "publish-images.yml",
            r"^\s+VERSION=(\d+\.\d+\.\d+)$",
            "published image build version",
        ),
        (
            root / "deploy" / "scripts" / "backup.sh",
            r"FLOWPROOF_APPLICATION_VERSION:-(\d+\.\d+\.\d+)",
            "backup metadata default version",
        ),
        (
            root / "backend" / "src" / "flowproof" / "main_routes_common.py",
            r'\{"status": "live", "version": "(\d+\.\d+\.\d+)"\}',
            "liveness response version",
        ),
        (
            root / "backend" / "src" / "flowproof" / "observability.py",
            r'^\s+"version": "(\d+\.\d+\.\d+)",$',
            "structured log version",
        ),
        (
            root / "backend" / "src" / "flowproof" / "evidence_legacy_v1_core.py",
            r'^EVIDENCE_PACKAGE_VERSION = "(\d+\.\d+\.\d+)"$',
            "evidence runtime package version",
        ),
        (
            root / "scripts" / "validate_deployment_proof_result.py",
            r'"version": "(\d+\.\d+\.\d+)"',
            "deployment proof contract version",
        ),
        (
            root / "productization" / "windows" / "Build-FlowProofWindowsAsset.ps1",
            r'^\s+\[string\]\$ApplicationVersion = "(\d+\.\d+\.\d+)",$',
            "Windows asset default version",
        ),
    )
    for path, pattern, label in regex_sources:
        versions.update(_regex_versions(path, pattern, label))
    return versions


def find_mismatches(versions: dict[str, str]) -> list[str]:
    canonical = versions["backend project.version"]
    return [
        f"{label}: found {version!r}; expected {canonical!r}"
        for label, version in versions.items()
        if version != canonical
    ]


def main() -> int:
    try:
        mismatches = find_mismatches(collect_versions())
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"Version consistency check could not read metadata: {exc}")
        return 1
    if mismatches:
        print("Version consistency check failed:")
        print("\n".join(f"- {mismatch}" for mismatch in mismatches))
        return 1
    print(f"Version consistency check passed: {collect_versions()['backend project.version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
