"""Terraform checks: public storage, admin ports open to the internet, public databases, disabled encryption."""

from __future__ import annotations

import re
from dataclasses import dataclass

from backend.repository.code_issues import SecurityIssue, snippet, suppressed

_RESOURCE = re.compile(r"^\s*resource\s+\"([^\"]+)\"\s+\"([^\"]+)\"\s*\{", re.MULTILINE)
_ATTRIBUTE_RULES = (
    ("REPO-IAC-008", re.compile(r"\bacl\s*=\s*\"public-read(?:-write)?\""), "The bucket ACL makes its objects readable by anyone."),
    ("REPO-IAC-008", re.compile(r"\b(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b"),
     "The public access block is switched off, so a bucket policy or ACL can expose the data."),
    ("REPO-IAC-008", re.compile(r"\b(?:allow_nested_items_to_be_public|allow_blob_public_access)\s*=\s*true\b"),
     "The storage account allows anonymous public access to blobs."),
    ("REPO-IAC-008", re.compile(r"\"(?:allUsers|allAuthenticatedUsers)\""), "Access is granted to every internet user."),
    ("REPO-IAC-010", re.compile(r"\bpublicly_accessible\s*=\s*true\b"), "The database is reachable from the internet."),
    ("REPO-IAC-011", re.compile(r"\b(?:encrypted|storage_encrypted|encryption_enabled|enable_encryption)\s*=\s*false\b"),
     "Encryption at rest is turned off."),
)
_WORLD = re.compile(r"\"(?:0\.0\.0\.0/0|::/0|\*|Internet|Any)\"")
_ADMIN_PORTS = (22, 3389)
ALL_PORTS = range(65536)


@dataclass
class Block:
    kind: str
    line: int
    text: str


def _close(text: str, opening: int) -> int:
    """Index just past the brace matching ``text[opening]``, ignoring braces inside strings."""
    depth, quoted = 0, False
    for index in range(opening, len(text)):
        char = text[index]
        if char == "\"" and text[index - 1] != "\\":
            quoted = not quoted
        elif not quoted and char in "{}":
            depth += 1 if char == "{" else -1
            if depth == 0:
                return index + 1
    return len(text)


def _blocks(text: str, pattern: re.Pattern[str]) -> list[Block]:
    return [
        Block(match.group(1) if match.groups() else "", text[: match.start()].count("\n") + 1,
              text[match.start(): _close(text, match.end() - 1)])
        for match in pattern.finditer(text)
    ]


def _listed_ports(text: str) -> range | None:
    """First listed port range covering an admin port, from Azure/GCP-style `"22"`, `"1000-2000"` or `"*"` strings."""
    for start, end, star in re.findall(r"\"(\d+)(?:-(\d+))?\"|\"(\*)\"", text):
        if star:
            return ALL_PORTS
        ports = range(int(start), int(end or start) + 1)
        if any(port in ports for port in _ADMIN_PORTS):
            return ports
    return None


def _port_range(text: str) -> range | None:
    if re.search(r"\bprotocol\s*=\s*\"(?:-1|all|\*)\"", text, re.IGNORECASE):
        return ALL_PORTS
    low, high = re.search(r"\bfrom_port\s*=\s*(\d+)", text), re.search(r"\bto_port\s*=\s*(\d+)", text)
    if low and high:
        return range(int(low.group(1)), int(high.group(1)) + 1)
    listed = re.search(r"destination_port_ranges?\s*=\s*(\[[^\]]*\]|\"[^\"]*\")", text)
    return _listed_ports(listed.group(1)) if listed else None


def _gcp_ports(text: str) -> range | None:
    allow = re.search(r"allow\s*\{([^}]*)\}", text)
    if not allow:
        return None
    if not re.search(r"\bports\s*=", allow.group(1)):
        return ALL_PORTS
    return _listed_ports(allow.group(1))


_NESTED_RULES = {
    "aws_security_group": ("aws_security_group", re.compile(r"\bingress\s*\{")),
    "azurerm_network_security_group": ("azurerm_network_security_rule", re.compile(r"\bsecurity_rule\s*\{")),
}


def _rule_segments(block: Block) -> list[Block]:
    if block.kind not in _NESTED_RULES:
        return [block]
    kind, pattern = _NESTED_RULES[block.kind]
    return [Block(kind, block.line + segment.line - 1, segment.text) for segment in _blocks(block.text, pattern)]


def _inbound(segment: Block) -> bool:
    if segment.kind == "aws_security_group_rule":
        return bool(re.search(r"\btype\s*=\s*\"ingress\"", segment.text))
    if segment.kind == "azurerm_network_security_rule":
        return bool(re.search(r"direction\s*=\s*\"Inbound\"", segment.text) and re.search(r"access\s*=\s*\"Allow\"", segment.text))
    if segment.kind == "google_compute_firewall":
        return not re.search(r"direction\s*=\s*\"EGRESS\"", segment.text)
    return segment.kind in ("aws_security_group", "aws_vpc_security_group_ingress_rule")


def _open_admin_port(segment: Block) -> bool:
    if not _inbound(segment) or not _WORLD.search(segment.text):
        return False
    ports = _gcp_ports(segment.text) if segment.kind == "google_compute_firewall" else _port_range(segment.text)
    return ports is not None and any(port in ports for port in _ADMIN_PORTS)


def _network_issues(path: str, block: Block) -> list[SecurityIssue]:
    return [
        SecurityIssue("REPO-IAC-009", path, segment.line,
                      "Inbound SSH or RDP (or every port) is open to the whole internet.", snippet(segment.text.splitlines()[0]))
        for segment in _rule_segments(block)
        if _open_admin_port(segment) and not suppressed(segment.text.splitlines()[0])
    ]


def _attribute_issues(path: str, block: Block) -> list[SecurityIssue]:
    issues = []
    for offset, line in enumerate(block.text.splitlines()):
        if suppressed(line) or line.lstrip().startswith(("#", "//")):
            continue
        for rule_id, pattern, message in _ATTRIBUTE_RULES:
            if pattern.search(line):
                issues.append(SecurityIssue(rule_id, path, block.line + offset, f"{message} (`{block.kind}`)", snippet(line)))
                break
    return issues


def terraform_issues(path: str, text: str) -> list[SecurityIssue]:
    issues = []
    for block in _blocks(text, _RESOURCE):
        issues += _attribute_issues(path, block) + _network_issues(path, block)
    return sorted(issues, key=lambda issue: issue.line)
