"""
Maintainability metrics for first-party source code.

Python is analysed through its syntax tree (complexity, size, unused
names, unreachable statements, docstrings, annotations). Other languages
get language-neutral measures: size, branch density and duplication.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from backend.repository.manifests import iter_files

SOURCE_SUFFIXES = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".kt": "Kotlin",
    ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".scala": "Scala",
    ".swift": "Swift", ".rs": "Rust", ".c": "C", ".cpp": "C++", ".h": "C",
}

MAX_SOURCE_BYTES = 1024 * 1024

COMPLEXITY_WARNING = 10
COMPLEXITY_HIGH = 20
COGNITIVE_WARNING = 15
FUNCTION_LINES = 60
PARAMETERS = 6
CLASS_METHODS = 25
CLASS_LINES = 600
FILE_LINES = 1000
DUPLICATE_WINDOW = 8
MAX_DUPLICATE_BLOCKS = 50

_BRANCH = re.compile(r"\b(if|for|while|case|catch|elif|unless|until)\b|&&|\|\||\?\s*[^:?]+:")
_COMMENT_LINE = re.compile(r"^\s*(#|//|/\*|\*|--)")


@dataclass
class Issue:
    rule_id: str
    path: str
    line: int
    symbol: str = ""
    message: str = ""
    metric: float | None = None
    end_line: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FunctionMetrics:
    path: str
    name: str
    line: int
    lines: int
    cyclomatic: int
    cognitive: int
    parameters: int


@dataclass
class QualityReport:
    files: int = 0
    code_lines: int = 0
    languages: dict[str, int] = field(default_factory=dict)
    functions: list[FunctionMetrics] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    duplicated_lines: int = 0
    documented: int = 0
    documentable: int = 0
    annotated: int = 0
    annotatable: int = 0
    has_readme: bool = False
    api_specs: list[str] = field(default_factory=list)
    has_web_api: bool = False

    def metrics(self) -> dict[str, Any]:
        complexities = [function.cyclomatic for function in self.functions]
        lines_in_complex = sum(function.lines for function in self.functions if function.cyclomatic > COMPLEXITY_WARNING)
        function_lines = sum(function.lines for function in self.functions) or 1

        return {
            "files": self.files,
            "code_lines": self.code_lines,
            "languages": self.languages,
            "functions": len(self.functions),
            "average_complexity": round(sum(complexities) / len(complexities), 2) if complexities else 0,
            "max_complexity": max(complexities, default=0),
            "complex_functions": sum(1 for value in complexities if value > COMPLEXITY_WARNING),
            "complex_code_ratio": round(lines_in_complex / function_lines, 4) if self.functions else 0,
            "duplicated_lines": self.duplicated_lines,
            "duplication_ratio": round(self.duplicated_lines / self.code_lines, 4) if self.code_lines else 0,
            "docstring_coverage": round(self.documented / self.documentable, 4) if self.documentable else None,
            "type_annotation_coverage": round(self.annotated / self.annotatable, 4) if self.annotatable else None,
            "has_readme": self.has_readme,
            "api_specs": self.api_specs,
            "has_web_api": self.has_web_api,
            "technical_debt_minutes": technical_debt_minutes(self.issues),
        }

    def hotspots(self, limit: int = 10) -> list[dict[str, Any]]:
        ranked = sorted(self.functions, key=lambda item: (-item.cyclomatic, -item.lines))

        return [asdict(item) for item in ranked[:limit]]


# Rough remediation effort per issue, in minutes, in the SQALE spirit.
DEBT_MINUTES = {
    "REPO-MNT-001": 30, "REPO-MNT-002": 20, "REPO-MNT-003": 15, "REPO-MNT-004": 60,
    "REPO-MNT-005": 2, "REPO-MNT-006": 5, "REPO-MNT-007": 5, "REPO-MNT-008": 20,
    "REPO-MNT-009": 120, "REPO-MNT-010": 120, "REPO-MNT-011": 30, "REPO-MNT-012": 120,
    "REPO-MNT-013": 30,
}


def technical_debt_minutes(issues: list[Issue]) -> int:
    return sum(DEBT_MINUTES.get(issue.rule_id, 10) for issue in issues)


# ------------------------------------------------------------- Python AST


_DECISIONS = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert)


def cyclomatic_complexity(node: ast.AST) -> int:
    """McCabe complexity of one function, not counting nested functions."""

    complexity = 1

    for child in _walk_own(node):
        if isinstance(child, _DECISIONS):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            complexity += len(child.values) - 1
        elif isinstance(child, ast.comprehension):
            complexity += 1 + len(child.ifs)
        elif hasattr(ast, "match_case") and isinstance(child, ast.match_case):
            complexity += 1

    return complexity


def cognitive_complexity(node: ast.AST) -> int:
    """
    Cognitive complexity (after G. Ann Campbell): each break in linear
    flow costs one, plus one per level of nesting it sits at.
    """

    total = 0

    def visit(current: ast.AST, nesting: int) -> None:
        nonlocal total

        for child in ast.iter_child_nodes(current):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                visit(child, nesting + 1) if isinstance(child, ast.Lambda) else None
                continue

            if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp)):
                is_elif = (
                    isinstance(current, ast.If)
                    and isinstance(child, ast.If)
                    and current.orelse == [child]
                )
                total += 1 if is_elif else 1 + nesting
                visit(child, nesting if is_elif else nesting + 1)
                continue

            if isinstance(child, ast.BoolOp):
                total += 1

            if isinstance(child, (ast.Break, ast.Continue)) and nesting > 1:
                total += 1

            visit(child, nesting)

    visit(node, 0)

    return total


def _walk_own(node: ast.AST):
    stack = list(ast.iter_child_nodes(node))

    while stack:
        child = stack.pop()

        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue

        yield child

        stack.extend(ast.iter_child_nodes(child))


def _span(node: ast.AST) -> int:
    end = getattr(node, "end_lineno", None) or getattr(node, "lineno", 0)

    return end - getattr(node, "lineno", 0) + 1


def _unused_locals(function: ast.AST) -> list[tuple[str, int]]:
    stored: dict[str, int] = {}
    loaded: set[str] = set()
    declared_outer: set[str] = set()

    # Only this function's own bindings count, but a nested function or
    # class reading a name (a closure) uses it.
    for child in _walk_own(function):
        if isinstance(child, (ast.Global, ast.Nonlocal)):
            declared_outer.update(child.names)
        elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
            stored.setdefault(child.id, child.lineno)

    for child in ast.walk(function):
        if isinstance(child, ast.Name) and not isinstance(child.ctx, ast.Store):
            loaded.add(child.id)

    # Names unpacked in a loop or tuple target are routinely partly unused.
    unpacked: set[str] = set()

    for child in ast.walk(function):
        targets = []

        if isinstance(child, (ast.For, ast.AsyncFor, ast.comprehension)):
            targets.append(child.target)
        elif isinstance(child, ast.Assign):
            targets.extend(target for target in child.targets if isinstance(target, (ast.Tuple, ast.List)))
        elif isinstance(child, ast.withitem) and child.optional_vars is not None:
            targets.append(child.optional_vars)

        for target in targets:
            unpacked.update(name.id for name in ast.walk(target) if isinstance(name, ast.Name))

    return [
        (name, line)
        for name, line in stored.items()
        if name not in loaded
        and name not in declared_outer
        and name not in unpacked
        and not name.startswith("_")
    ]


def _unreachable(body: list[ast.stmt]) -> list[ast.stmt]:
    found = []

    for index, statement in enumerate(body[:-1]):
        if isinstance(statement, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            found.append(body[index + 1])
            break

    for statement in body:
        for name in ("body", "orelse", "finalbody"):
            nested = getattr(statement, name, None)

            if isinstance(nested, list) and nested and isinstance(nested[0], ast.stmt):
                found.extend(_unreachable(nested))

        for handler in getattr(statement, "handlers", []) or []:
            found.extend(_unreachable(handler.body))

    return found


def _analyse_class(node: ast.ClassDef, path: str, report: QualityReport, is_test: bool) -> None:
    methods = [
        child for child in node.body
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if len(methods) > CLASS_METHODS or _span(node) > CLASS_LINES:
        report.issues.append(
            Issue("REPO-MNT-004", path, node.lineno, node.name,
                  f"Class `{node.name}` has {len(methods)} methods over {_span(node)} lines.",
                  float(_span(node)), node.end_lineno or node.lineno)
        )

    if not is_test and not node.name.startswith("_"):
        report.documentable += 1
        report.documented += ast.get_docstring(node) is not None


def _analyse_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    path: str,
    report: QualityReport,
    is_test: bool,
) -> None:
    cyclomatic = cyclomatic_complexity(node)
    cognitive = cognitive_complexity(node)
    arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    parameters = [argument for argument in arguments if argument.arg not in ("self", "cls")]
    report.functions.append(
        FunctionMetrics(path, node.name, node.lineno, _span(node), cyclomatic, cognitive, len(parameters))
    )
    end = node.end_lineno or node.lineno

    if cyclomatic > COMPLEXITY_WARNING or cognitive > COGNITIVE_WARNING:
        report.issues.append(
            Issue("REPO-MNT-001", path, node.lineno, node.name,
                  f"`{node.name}` has cyclomatic complexity {cyclomatic} and cognitive complexity {cognitive}.",
                  float(cyclomatic), end)
        )
    if _span(node) > FUNCTION_LINES:
        report.issues.append(
            Issue("REPO-MNT-002", path, node.lineno, node.name,
                  f"`{node.name}` is {_span(node)} lines long.", float(_span(node)), end)
        )
    if len(parameters) > PARAMETERS:
        report.issues.append(
            Issue("REPO-MNT-003", path, node.lineno, node.name,
                  f"`{node.name}` takes {len(parameters)} parameters.", float(len(parameters)), end)
        )
    for name, line in _unused_locals(node):
        report.issues.append(
            Issue("REPO-MNT-006", path, line, name, f"Local variable `{name}` in `{node.name}` is assigned but never used.")
        )

    if not node.name.startswith("_") and not is_test:
        report.documentable += 1
        report.documented += ast.get_docstring(node) is not None
        report.annotatable += 1
        report.annotated += node.returns is not None and all(
            argument.annotation is not None for argument in parameters
        )


def _analyse_python(path: str, source: str, report: QualityReport) -> None:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return

    is_test = bool(re.search(r"(^|/)(tests?|test_[^/]*|[^/]*_test)\.?", path))

    if re.search(r"\b(flask|fastapi|django|starlette)\b", source) and re.search(r"@\w+\.(route|get|post|put|delete|api_view)", source):
        report.has_web_api = True

    if not is_test:
        report.documentable += 1
        report.documented += ast.get_docstring(tree) is not None

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            _analyse_class(node, path, report, is_test)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _analyse_function(node, path, report, is_test)

    for statement in _unreachable(tree.body):
        report.issues.append(
            Issue("REPO-MNT-007", path, statement.lineno, "", "Statement can never run: it follows a return, raise, break or continue.")
        )

    if not path.endswith("__init__.py"):
        _unused_imports(path, tree, report)


def _unused_imports(path: str, tree: ast.Module, report: QualityReport) -> None:
    imported: dict[str, int] = {}

    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[(alias.asname or alias.name).split(".")[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
            for alias in node.names:
                if alias.name != "*":
                    imported[alias.asname or alias.name] = node.lineno

    used: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                used.add(root.id)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            # Names referenced from string annotations and __all__.
            used.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", node.value))

    for name, line in imported.items():
        if name not in used:
            report.issues.append(Issue("REPO-MNT-005", path, line, name, f"`{name}` is imported but never used."))


# ---------------------------------------------------- language-neutral


def _analyse_generic(path: str, lines: list[str], report: QualityReport) -> None:
    branches = sum(len(_BRANCH.findall(line)) for line in lines if not _COMMENT_LINE.match(line))

    if len(lines) > FILE_LINES:
        report.issues.append(
            Issue("REPO-MNT-004", path, 1, "", f"File has {len(lines)} lines and {branches} branch points.", float(len(lines)), len(lines))
        )


def _normalised_lines(text: str) -> list[tuple[int, str]]:
    lines = []

    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()

        if not stripped or _COMMENT_LINE.match(stripped) or stripped in ("{", "}", ")", "]", "});", "end", "pass"):
            continue

        if stripped.startswith(("import ", "from ", "#include", "using ", "package ", "require")):
            continue

        lines.append((number, re.sub(r"\s+", " ", stripped)))

    return lines


def _duplicates(sources: dict[str, list[tuple[int, str]]], report: QualityReport) -> None:
    windows: dict[str, list[tuple[str, int]]] = {}

    for path, lines in sources.items():
        for index in range(len(lines) - DUPLICATE_WINDOW + 1):
            chunk = "\n".join(text for _, text in lines[index:index + DUPLICATE_WINDOW])

            if len(chunk) < DUPLICATE_WINDOW * 8:
                continue

            digest = hashlib.sha1(chunk.encode("utf-8")).hexdigest()
            windows.setdefault(digest, []).append((path, index))

    duplicated: dict[str, set[int]] = {}
    first_copy: dict[tuple[str, int], tuple[str, int]] = {}

    for occurrences in windows.values():
        if len(occurrences) < 2:
            continue

        original = occurrences[0]

        for path, index in occurrences:
            duplicated.setdefault(path, set()).update(range(index, index + DUPLICATE_WINDOW))

            if (path, index) != original:
                first_copy.setdefault((path, index), original)

    report.duplicated_lines = sum(len(indexes) for indexes in duplicated.values())

    # Collapse overlapping windows into one block per copy.
    reported = 0
    covered: dict[str, int] = {}

    for (path, index), (original_path, original_index) in sorted(first_copy.items()):
        if index < covered.get(path, -1) or reported >= MAX_DUPLICATE_BLOCKS:
            continue

        end = index + DUPLICATE_WINDOW

        while (path, end - DUPLICATE_WINDOW + 1) in first_copy:
            end += 1

        covered[path] = end

        lines = sources[path]
        start_line = lines[index][0]
        end_line = lines[min(end, len(lines)) - 1][0]
        original_line = sources[original_path][original_index][0]

        report.issues.append(
            Issue("REPO-MNT-008", path, start_line, "",
                  f"Lines {start_line}-{end_line} duplicate {original_path}:{original_line}.",
                  float(end - index), end_line)
        )
        reported += 1


def _analyse_source_file(
    path: Path,
    root: Path,
    report: QualityReport,
    normalised: dict[str, list[tuple[int, str]]],
) -> None:
    relative = path.relative_to(root).as_posix()
    name = path.name.lower()
    if name.startswith("readme"):
        if path.parent == root:
            report.has_readme = True
        return

    if re.fullmatch(r"(openapi|swagger)[^/]*\.(ya?ml|json)", name) or name.endswith((".raml", ".graphql")):
        report.api_specs.append(relative)
        return

    language = SOURCE_SUFFIXES.get(path.suffix.lower())
    if language is None or path.stat().st_size > MAX_SOURCE_BYTES:
        return
    if re.search(r"\.min\.(js|css)$|(^|/)(migrations|fixtures|generated)/", relative):
        return

    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    report.files += 1
    code = _normalised_lines(text)
    report.code_lines += len(code)
    report.languages[language] = report.languages.get(language, 0) + len(code)
    normalised[relative] = code

    if language == "Python":
        _analyse_python(relative, text, report)
        if len(lines) > FILE_LINES:
            _analyse_generic(relative, lines, report)
    else:
        _analyse_generic(relative, lines, report)
        if language in ("JavaScript", "TypeScript") and re.search(r"\b(express|fastify|koa)\b", text):
            report.has_web_api = True


def _coverage_issues(report: QualityReport) -> None:
    metrics = report.metrics()
    if metrics["docstring_coverage"] is not None and report.documentable >= 10 and metrics["docstring_coverage"] < 0.5:
        report.issues.append(
            Issue("REPO-MNT-009", "", 0, "", f"Only {metrics['docstring_coverage']:.0%} of public modules, classes and functions have a docstring.",
                  metrics["docstring_coverage"])
        )

    if metrics["type_annotation_coverage"] is not None and report.annotatable >= 10 and metrics["type_annotation_coverage"] < 0.5:
        report.issues.append(
            Issue("REPO-MNT-010", "", 0, "", f"Only {metrics['type_annotation_coverage']:.0%} of public functions are fully type-annotated.",
                  metrics["type_annotation_coverage"])
        )


def analyse_quality(root: Path) -> QualityReport:
    report = QualityReport()
    normalised: dict[str, list[tuple[int, str]]] = {}
    for path in iter_files(root):
        _analyse_source_file(path, root, report, normalised)

    _duplicates(normalised, report)
    if not report.has_readme and report.files:
        report.issues.append(Issue("REPO-MNT-011", "README.md", 0, "", "The repository has no README at its root."))
    if report.has_web_api and not report.api_specs:
        report.issues.append(Issue("REPO-MNT-013", "", 0, "", "The code serves an HTTP API but no OpenAPI/Swagger specification was found."))
    _coverage_issues(report)
    return report
