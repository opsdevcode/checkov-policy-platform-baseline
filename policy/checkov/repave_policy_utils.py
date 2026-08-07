from __future__ import annotations

import os
import re
from pathlib import Path

VARIABLE_BLOCK_PATTERN = re.compile(r'^\s*variable\s+"([^"]+)"\s*\{', re.MULTILINE)
RESOURCE_BLOCK_PATTERN = re.compile(r'^\s*resource\s+"', re.MULTILINE)


def candidate_scan_roots() -> list[Path]:
    roots: list[Path] = []
    env_root = os.environ.get("REPAVE_CHECKOV_SCAN_ROOT")
    if env_root:
        roots.append(Path(env_root))
    roots.append(Path.cwd())
    return roots


def resolve_module_root(scanned_file: str) -> Path:
    path = Path(scanned_file)
    if path.is_file():
        start = path.parent
    else:
        filename = path.name
        start = None
        for root in candidate_scan_roots():
            candidate = root / filename
            if candidate.is_file():
                start = root
                break
        if start is None:
            start = Path.cwd()

    current = start.resolve()
    while True:
        if (current / "versions.tf").is_file():
            return current
        if current.parent == current:
            return start.resolve()
        current = current.parent


def module_dir(scanned_file: str) -> Path:
    return resolve_module_root(scanned_file)


def read_module_file(module_root: Path, filename: str) -> str | None:
    path = module_root / filename
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def read_scanned_resource_file(scanned_file: str) -> str | None:
    path = Path(scanned_file)
    if path.is_file():
        return path.read_text(encoding="utf-8")

    filename = path.name
    for root in candidate_scan_roots():
        candidate = root / filename
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    return None


def declared_variable_names(module_root: Path) -> set[str]:
    content = read_module_file(module_root, "variables.tf")
    if content is None:
        return set()
    return set(VARIABLE_BLOCK_PATTERN.findall(content))


def file_contains_resource_blocks(content: str) -> bool:
    return RESOURCE_BLOCK_PATTERN.search(content) is not None


def references_shared_locals(content: str) -> bool:
    normalized = content.replace(" ", "")
    return "local.name_prefix" in normalized and "local.common_tags" in normalized


ALLOCATION_TAG_BINDINGS = (
    ("Owner", "var.owner"),
    ("Service", "var.service"),
    ("Environment", "var.environment"),
    ("CostCenter", "var.cost_center"),
)


def common_tags_include_allocation_tags(content: str) -> bool:
    normalized = content.replace(" ", "").replace("\n", "")
    if "common_tags" not in normalized:
        return False
    return all(f"{key}={binding}" in normalized for key, binding in ALLOCATION_TAG_BINDINGS)


def iter_tf_files(module_root: Path) -> list[Path]:
    return sorted(path for path in module_root.glob("*.tf") if path.is_file())


def module_tf_contents(module_root: Path) -> dict[str, str]:
    return {path.name: path.read_text(encoding="utf-8") for path in iter_tf_files(module_root)}


AWS_ACCESS_KEY_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")
GITHUB_TOKEN_PATTERN = re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")
GITLAB_PAT_PATTERN = re.compile(r"glpat-[A-Za-z0-9\-_]{20,}")
PROVIDER_CREDENTIAL_ATTR_PATTERN = re.compile(
    r"(?:access_key|secret_key|client_secret|password|api_key)\s*=\s*\"[^\"]+\"",
    re.IGNORECASE,
)
PROVISIONER_PATTERN = re.compile(r'provisioner\s+"(?:local-exec|remote-exec)"')
OUTPUT_BLOCK_PATTERN = re.compile(r'output\s+"([^"]+)"\s*\{', re.MULTILINE)
SENSITIVE_OUTPUT_NAME_PATTERN = re.compile(
    r"(password|secret|token|private_key|api_key)",
    re.IGNORECASE,
)


def file_contains_hardcoded_secrets(content: str) -> bool:
    return bool(
        AWS_ACCESS_KEY_PATTERN.search(content)
        or PRIVATE_KEY_PATTERN.search(content)
        or GITHUB_TOKEN_PATTERN.search(content)
        or GITLAB_PAT_PATTERN.search(content)
    )


def file_contains_provider_credentials(content: str) -> bool:
    if 'provider "' not in content:
        return False
    return bool(PROVIDER_CREDENTIAL_ATTR_PATTERN.search(content))


def file_contains_provisioners(content: str) -> bool:
    return bool(PROVISIONER_PATTERN.search(content))


def sensitive_output_names_missing_flag(content: str) -> list[str]:
    missing: list[str] = []
    for match in OUTPUT_BLOCK_PATTERN.finditer(content):
        name = match.group(1)
        if not SENSITIVE_OUTPUT_NAME_PATTERN.search(name):
            continue
        block_start = match.end() - 1
        depth = 0
        block_end = block_start
        for index in range(block_start, len(content)):
            char = content[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    block_end = index
                    break
        block_body = content[block_start : block_end + 1]
        if "sensitive" not in block_body:
            missing.append(name)
    return missing
