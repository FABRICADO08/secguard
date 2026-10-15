"""Syntax-tree security checks for first-party Python code."""

from __future__ import annotations

import ast
import re

from backend.repository.code_issues import SecurityIssue, snippet, suppressed

SQL_KEYWORD = re.compile(r"\b(?:select|insert|update|delete|create|drop|alter|merge)\b", re.IGNORECASE)
SQL_SINKS = frozenset({"execute", "executemany", "executescript", "raw", "extra", "text", "read_sql", "read_sql_query"})
SHELL_CALLS = frozenset({"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput", "commands.getoutput"})
SUBPROCESS_CALLS = frozenset({"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"})
CODE_CALLS = frozenset({"eval", "exec"})
DESERIALIZERS = frozenset(
    {
        "pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "dill.load", "dill.loads",
        "marshal.load", "marshal.loads", "jsonpickle.decode", "shelve.open", "pandas.read_pickle",
        "yaml.unsafe_load", "yaml.full_load", "torch.load",
    }
)
HTTP_CALLS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request", "Client", "AsyncClient", "stream"})

MESSAGES = {
    "REPO-SEC-001": "SQL statement built from {how} is passed to `{call}`; untrusted input in it can change the query.",
    "REPO-SEC-002": "`{call}` runs a shell command built at runtime; untrusted input in it can run arbitrary commands.",
    "REPO-SEC-003": "`{call}` evaluates code that is built at runtime.",
    "REPO-SEC-004": "`{call}` deserializes data in a format that can execute code while loading.",
    "REPO-SEC-007": "`{call}` is called with `verify=False`, which disables TLS certificate validation.",
    "REPO-SEC-008": "`{call}` enables debug mode, which exposes an interactive debugger and stack traces.",
}


def _aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def call_name(call: ast.Call, aliases: dict[str, str]) -> str:
    name = _dotted(call.func)
    head, _, rest = name.partition(".")
    resolved = aliases.get(head, head)
    return f"{resolved}.{rest}" if rest else resolved


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((keyword.value for keyword in call.keywords if keyword.arg == name), None)


def _is_constant(node: ast.expr | None, value: object) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


def _string_parts(node: ast.AST) -> str:
    return " ".join(
        child.value for child in ast.walk(node) if isinstance(child, ast.Constant) and isinstance(child.value, str)
    )


def runtime_value(node: ast.expr) -> bool:
    """Whether evaluating the expression reads anything other than literals."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Constant):
        return any(runtime_value(value) for value in [*node.args, *(keyword.value for keyword in node.keywords)])
    return any(isinstance(child, (ast.Name, ast.Attribute, ast.Call, ast.Subscript)) for child in ast.walk(node))


def _interpolated(node: ast.expr) -> bool:
    return isinstance(node, ast.JoinedStr) and any(isinstance(value, ast.FormattedValue) for value in node.values)


def _operator(node: ast.expr) -> str:
    if not isinstance(node, ast.BinOp) or not _string_parts(node):
        return ""
    return {ast.Add: "string concatenation", ast.Mod: "%-formatting"}.get(type(node.op), "")


def _format_call(node: ast.expr) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"


def built_string(node: ast.expr) -> str:
    """How a string is assembled at runtime, or "" when it is a literal."""
    if not runtime_value(node):
        return ""
    if _interpolated(node):
        return "an f-string"
    if _format_call(node):
        return "str.format()"
    return _operator(node)


def _first_argument(call: ast.Call) -> ast.expr | None:
    if call.args:
        return call.args[0]
    return _keyword(call, "args") or _keyword(call, "sql") or _keyword(call, "query")


def _sql(call: ast.Call, name: str) -> tuple[str, dict[str, str]] | None:
    argument = _first_argument(call)
    if name.rpartition(".")[2] not in SQL_SINKS or argument is None:
        return None
    how = built_string(argument)
    if how and SQL_KEYWORD.search(_string_parts(argument)):
        return "REPO-SEC-001", {"how": how}
    return None


def _command(call: ast.Call, name: str) -> tuple[str, dict[str, str]] | None:
    argument = _first_argument(call)
    dynamic = argument is not None and runtime_value(argument)
    if name in SHELL_CALLS and dynamic:
        return "REPO-SEC-002", {}
    if name in SUBPROCESS_CALLS and dynamic and _is_constant(_keyword(call, "shell"), True):
        return "REPO-SEC-002", {}
    return None


def _code(call: ast.Call, name: str) -> tuple[str, dict[str, str]] | None:
    if name in CODE_CALLS and call.args and runtime_value(call.args[0]):
        return "REPO-SEC-003", {}
    return None


def _deserialization(call: ast.Call, name: str) -> tuple[str, dict[str, str]] | None:
    if name in DESERIALIZERS:
        return "REPO-SEC-004", {}
    if name == "yaml.load":
        loader = _dotted(_keyword(call, "Loader") or (call.args[1] if len(call.args) > 1 else ast.Constant(None)))
        if not loader.endswith("SafeLoader"):
            return "REPO-SEC-004", {}
    return None


def _transport(call: ast.Call, name: str) -> tuple[str, dict[str, str]] | None:
    if name.rpartition(".")[2] in HTTP_CALLS and _is_constant(_keyword(call, "verify"), False):
        return "REPO-SEC-007", {}
    if name.endswith(".run") and _is_constant(_keyword(call, "debug"), True):
        return "REPO-SEC-008", {}
    return None


CHECKS = (_sql, _command, _code, _deserialization, _transport)


def _django_debug(tree: ast.Module, path: str, lines: list[str]) -> list[SecurityIssue]:
    if not path.endswith("settings.py"):
        return []
    return [
        SecurityIssue("REPO-SEC-008", path, node.lineno, "Django `DEBUG = True` is set in the settings module.", snippet(lines[node.lineno - 1]))
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "DEBUG" for target in node.targets)
        and _is_constant(node.value, True)
        and not suppressed(lines[node.lineno - 1])
    ]


def python_issues(path: str, text: str) -> list[SecurityIssue]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    lines = text.splitlines()
    aliases = _aliases(tree)
    issues = _django_debug(tree, path, lines)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = call_name(node, aliases)
        line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
        for check in CHECKS:
            found = check(node, name)
            if found and not suppressed(line):
                rule_id, extra = found
                message = MESSAGES[rule_id].format(call=name, **extra)
                issues.append(SecurityIssue(rule_id, path, node.lineno, message, snippet(line)))
                break
    return issues
