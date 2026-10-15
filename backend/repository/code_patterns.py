"""Line-pattern security checks for first-party code in non-Python languages."""

from __future__ import annotations

import re

from backend.repository.code_issues import SecurityIssue, snippet, suppressed
from backend.risk.confidence import FIRM, TENTATIVE

SQL = r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b"
JS = frozenset({"JavaScript", "TypeScript"})
JVM = frozenset({"Java", "Kotlin", "Scala"})

# (languages, rule, pattern, message, confidence)
PATTERNS: tuple[tuple[frozenset[str], str, re.Pattern[str], str, str], ...] = tuple(
    (languages, rule, re.compile(pattern, re.IGNORECASE), message, confidence)
    for languages, rule, pattern, message, confidence in (
        (JS, "REPO-SEC-001", r"\.(?:query|execute|raw|run|all|prepare)\s*\(\s*`[^`]*" + SQL + r"[^`]*\$\{",
         "SQL statement built with a template literal is passed to a query call.", FIRM),
        (JS, "REPO-SEC-001", r"\.(?:query|execute|raw)\s*\(\s*[\"'][^\"']*" + SQL + r"[^\"']*[\"']\s*\+",
         "SQL statement built by string concatenation is passed to a query call.", FIRM),
        (JS, "REPO-SEC-002", r"(?:(?<![.\w$])|child_process\.)(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^)\"'`,]*\+)",
         "Shell command built at runtime is passed to `child_process.exec`.", FIRM),
        (JS, "REPO-SEC-003", r"(?<![.\w$])eval\s*\(\s*(?![\"'`][^\"'`]*[\"'`]\s*\))[^)]",
         "`eval` runs code that is built at runtime.", FIRM),
        (JS, "REPO-SEC-003", r"\bnew\s+Function\s*\(", "`new Function` compiles code from a string.", TENTATIVE),
        (JS, "REPO-SEC-004", r"require\s*\(\s*[\"']node-serialize[\"']\s*\)",
         "`node-serialize` can execute functions embedded in serialized data.", FIRM),
        (JS, "REPO-SEC-007", r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED[\"'\]]*\s*=\s*[\"']?0",
         "TLS certificate validation is disabled.", FIRM),
        (JVM, "REPO-SEC-001",
         r"\b(?:executeQuery|executeUpdate|execute|addBatch|prepareStatement|createQuery|createNativeQuery|queryForList|queryForObject|query)\s*\(\s*\"[^\"]*"
         + SQL + r"[^\"]*\"\s*\+",
         "SQL statement built by string concatenation is passed to a query call.", FIRM),
        (JVM, "REPO-SEC-002", r"Runtime\.getRuntime\(\)\.exec\s*\((?!\s*\"[^\"]*\"\s*\))|new\s+ProcessBuilder\s*\([^)]*\+",
         "Process command is built at runtime.", FIRM),
        (JVM, "REPO-SEC-004", r"new\s+ObjectInputStream\s*\(|new\s+XMLDecoder\s*\(|\.enableDefaultTyping\s*\(",
         "Java native or polymorphic deserialization can instantiate attacker-chosen classes.", TENTATIVE),
        (JVM, "REPO-SEC-007", r"NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllStrategy",
         "TLS hostname or certificate validation is disabled.", FIRM),
        (frozenset({"C#"}), "REPO-SEC-001",
         r"new\s+(?:Sql|OleDb|Odbc|MySql|Npgsql|Sqlite)Command\s*\(\s*(?:\$\"[^\"]*\{|\"[^\"]*\"\s*\+)|\.(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync)\s*\(\s*(?:\$\"|\"[^\"]*\"\s*\+)",
         "SQL statement built with interpolation or concatenation is passed to a command.", FIRM),
        (frozenset({"C#"}), "REPO-SEC-002", r"(?:Process\.Start|new\s+ProcessStartInfo)\s*\([^)]*(?:\+|\$\")",
         "Process command is built at runtime.", TENTATIVE),
        (frozenset({"C#"}), "REPO-SEC-004",
         r"\b(?:BinaryFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter|ObjectStateFormatter)\b|TypeNameHandling\.(?:All|Auto|Objects)",
         "This .NET serializer can instantiate attacker-chosen types.", FIRM),
        (frozenset({"C#"}), "REPO-SEC-007",
         r"(?:ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback)\s*=.*=>\s*true|DangerousAcceptAnyServerCertificateValidator",
         "TLS certificate validation is disabled.", FIRM),
        (frozenset({"Go"}), "REPO-SEC-001",
         r"\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\s*\([^)]*(?:fmt\.Sprintf\s*\(\s*\"[^\"]*" + SQL + r"|\"[^\"]*" + SQL + r"[^\"]*\"\s*\+)",
         "SQL statement built with fmt.Sprintf or concatenation is passed to a query call.", FIRM),
        (frozenset({"Go"}), "REPO-SEC-002",
         r"exec\.Command(?:Context)?\s*\([^)]*\"(?:sh|bash|cmd|/bin/sh|/bin/bash)\"\s*,\s*\"(?:-c|/c)\"\s*,\s*(?!\"[^\"]*\"\s*\))",
         "Shell command built at runtime is passed to `sh -c`.", FIRM),
        (frozenset({"Go"}), "REPO-SEC-007", r"InsecureSkipVerify\s*:\s*true", "TLS certificate validation is disabled.", FIRM),
        (frozenset({"PHP"}), "REPO-SEC-001",
         r"(?:->query|mysqli?_query|pg_query)\s*\([^;]*[\"'][^\"']*" + SQL + r"[^\"']*(?:\$\w|[\"']\s*\.)",
         "SQL statement built from variables is passed to a query call.", FIRM),
        (frozenset({"PHP"}), "REPO-SEC-002", r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$\w",
         "Shell command built from variables is executed.", FIRM),
        (frozenset({"PHP"}), "REPO-SEC-003", r"\b(?:eval|assert)\s*\(\s*\$|preg_replace\s*\(\s*[\"'][^\"']*/e[\"']",
         "Code built from variables is evaluated.", FIRM),
        (frozenset({"PHP"}), "REPO-SEC-004", r"\bunserialize\s*\(\s*\$", "`unserialize` on variable data can instantiate objects.", FIRM),
        (frozenset({"PHP"}), "REPO-SEC-007", r"CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)\b",
         "TLS certificate validation is disabled.", FIRM),
        (frozenset({"Ruby"}), "REPO-SEC-001", r"\.(?:where|find_by_sql|execute|order|joins)\s*\(?\s*\"[^\"]*#\{",
         "SQL fragment built with string interpolation.", FIRM),
        (frozenset({"Ruby"}), "REPO-SEC-002", r"\b(?:system|exec|spawn)\s*\(?\s*\"[^\"]*#\{|`[^`]*#\{|%x\{[^}]*#\{",
         "Shell command built with string interpolation.", FIRM),
        (frozenset({"Ruby"}), "REPO-SEC-004", r"\bMarshal\.load\b|\bYAML\.load\s*\((?![^)]*permitted)",
         "This deserializer can instantiate arbitrary objects.", FIRM),
        (frozenset({"Ruby"}), "REPO-SEC-007", r"VERIFY_NONE", "TLS certificate validation is disabled.", FIRM),
    )
)

_COMMENT = re.compile(r"^\s*(?://|/\*|\*|#(?!\{))")


def pattern_issues(path: str, text: str, language: str) -> list[SecurityIssue]:
    rules = [rule for rule in PATTERNS if language in rule[0]]
    if not rules:
        return []
    issues: list[SecurityIssue] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if _COMMENT.match(line) or suppressed(line):
            continue
        for _, rule_id, pattern, message, confidence in rules:
            if pattern.search(line):
                issues.append(SecurityIssue(rule_id, path, number, message, snippet(line), confidence))
                break
    return issues
