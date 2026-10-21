from backend.repository.code_security import analyse_code_security
from backend.repository.health import security_health
from backend.repository.iac import infrastructure_issues
from backend.repository.ingest import application_from_report
from backend.repository.sarif import to_sarif
from backend.repository.scanner import scan_repository


def rules(issues):
    return sorted((issue.rule_id, issue.line) for issue in issues)


DOCKERFILE = """FROM node:20 AS build
RUN npm ci
FROM python
ENV API_TOKEN=abc123 PATH=/usr/bin
ARG DB_PASSWORD
RUN curl -fsSL https://example.test/install.sh \\
    | bash
ADD https://example.test/tool.tgz /opt/
ADD --checksum=sha256:00 https://example.test/ok.tgz /opt/
COPY --from=build /app /app
"""


def test_dockerfile_root_unpinned_secret_and_remote_scripts():
    issues = infrastructure_issues("Dockerfile", DOCKERFILE)
    assert rules(issues) == [
        ("REPO-IAC-001", 3), ("REPO-IAC-002", 3), ("REPO-IAC-003", 4), ("REPO-IAC-004", 6), ("REPO-IAC-004", 8),
    ]
    assert "abc123" not in str([issue.to_dict() for issue in issues])


def test_dockerfile_non_root_and_pinned_is_clean():
    text = "FROM python:3.12-slim@sha256:abc AS base\nFROM base\nUSER 10001\n"
    assert infrastructure_issues("deploy/api.Dockerfile", text) == []
    assert rules(infrastructure_issues("Containerfile", "FROM alpine:latest\nUSER app\nUSER root\n")) == [
        ("REPO-IAC-001", 3), ("REPO-IAC-002", 1),
    ]
    assert infrastructure_issues("Dockerfile", "FROM gcr.io/distroless/static:nonroot\n") == []


KUBERNETES = """apiVersion: v1
kind: ConfigMap
data: {}
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: api
          securityContext:
            privileged: true
            runAsUser: 0
      volumes:
        - name: docker
          hostPath:
            path: /var/run/docker.sock
"""


def test_kubernetes_privileges_root_and_limits():
    assert rules(infrastructure_issues("k8s/api.yaml", KUBERNETES)) == [
        ("REPO-IAC-005", 10), ("REPO-IAC-005", 14), ("REPO-IAC-005", 18), ("REPO-IAC-006", 15), ("REPO-IAC-007", 6),
    ]
    hardened = """apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
  containers:
    - name: api
      resources:
        limits:
          memory: 128Mi
"""
    assert infrastructure_issues("pod.yml", hardened) == []
    assert infrastructure_issues("config.yml", "name: not kubernetes\ncontainers: []\n") == []


TERRAFORM = """resource "aws_s3_bucket_acl" "site" {
  acl = "public-read"
}
resource "aws_s3_bucket_public_access_block" "site" {
  block_public_acls = false
}
resource "aws_db_instance" "main" {
  publicly_accessible = true
  storage_encrypted   = false
}
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "azurerm_network_security_rule" "rdp" {
  direction                  = "Inbound"
  access                     = "Allow"
  destination_port_range     = "3389"
  source_address_prefix      = "*"
}
resource "google_compute_firewall" "all" {
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
  }
}
resource "google_storage_bucket_iam_member" "public" {
  member = "allUsers"
}
resource "aws_security_group_rule" "office" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["10.0.0.0/8"]
}
"""


def test_terraform_public_storage_network_database_and_encryption():
    assert rules(infrastructure_issues("infra/main.tf", TERRAFORM)) == [
        ("REPO-IAC-008", 2), ("REPO-IAC-008", 5), ("REPO-IAC-008", 36), ("REPO-IAC-009", 17), ("REPO-IAC-009", 23),
        ("REPO-IAC-009", 29), ("REPO-IAC-010", 8), ("REPO-IAC-011", 9),
    ]


WORKFLOW = """on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some/action@v1
      - uses: some/action@0123456789abcdef0123456789abcdef01234567
      - uses: ./local
      - run: echo "${{ github.event.pull_request.title }}"
      - run: |
          echo building
          git checkout ${{ github.head_ref }}
      - name: Safe
        env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE ${{ github.event.repository.name }}"
"""


def test_workflow_permissions_checkout_injection_and_pinning():
    assert rules(infrastructure_issues(".github/workflows/ci.yml", WORKFLOW)) == [
        ("REPO-IAC-012", 1), ("REPO-IAC-013", 9), ("REPO-IAC-013", 16), ("REPO-IAC-014", 13), ("REPO-IAC-014", 16),
        ("REPO-IAC-015", 10),
    ]
    assert rules(infrastructure_issues(".github/workflows/a.yml", "on: push\npermissions: write-all\n")) == [("REPO-IAC-012", 2)]
    assert infrastructure_issues(".github/workflows/b.yml", "on: push\npermissions:\n  contents: read\n") == []


def test_suppression_and_test_paths_are_skipped():
    assert infrastructure_issues("Dockerfile", "FROM python:3.12 # secguard-ignore\n") == []
    assert infrastructure_issues("tests/fixtures/Dockerfile", "FROM python\n") == []
    assert infrastructure_issues("infra/main.tf", 'resource "aws_db_instance" "x" {\n  publicly_accessible = true # nosec\n}\n') == []


def _infra_repository(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python\n")
    (tmp_path / "main.tf").write_text('resource "aws_db_instance" "x" {\n  publicly_accessible = true\n}\n')
    return tmp_path


def test_code_security_includes_infrastructure_files(tmp_path):
    root = _infra_repository(tmp_path)
    assert rules(analyse_code_security(root, history=False)) == [("REPO-IAC-001", 1), ("REPO-IAC-002", 1), ("REPO-IAC-010", 2)]


def test_scan_reports_infrastructure_findings_and_lowers_security(tmp_path):
    report = scan_repository(_infra_repository(tmp_path), {"name": "acme/infra"})
    findings = [finding for finding in report["findings"] if finding["rule_id"].startswith("REPO-IAC-")]
    assert {finding["rule_id"] for finding in findings} == {"REPO-IAC-001", "REPO-IAC-002", "REPO-IAC-010"}
    database = next(finding for finding in findings if finding["rule_id"] == "REPO-IAC-010")
    assert (database["severity"], database["location"]) == ("high", "main.tf:2")
    assert security_health(findings) < 100


def test_infrastructure_findings_reach_sarif_and_storage(tmp_path):
    report = scan_repository(_infra_repository(tmp_path), {"name": "acme/infra"})
    assert {rule["id"] for rule in to_sarif(report)["runs"][0]["tool"]["driver"]["rules"]} >= {"REPO-IAC-010"}
    _, stored = application_from_report(report)
    assert any(finding["rule_id"] == "REPO-IAC-010" and finding["recommendation"] for finding in stored)
