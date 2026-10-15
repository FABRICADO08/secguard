from backend.repository.ingest import application_from_report
from backend.repository.maintainability import (
    component_of,
    gini,
    maintainability_rating,
    stars,
)
from backend.repository.quality import analyse_quality
from backend.repository.scanner import scan_repository
from backend.repository.units import Unit, brace_units, import_targets


def test_stars_cross_each_band_at_its_threshold():
    thresholds = (3, 5, 10, 20)

    assert stars(0, thresholds) == 5.5
    assert stars(3, thresholds) == 4.5
    assert stars(10, thresholds) == 2.5
    assert stars(500, thresholds) == 0.5


def test_brace_units_measure_size_complexity_and_parameters():
    source = """
class Cart {
    public int total(List<Item> items, int discount, boolean member) {
        int sum = 0;
        for (Item item : items) {
            if (item.active && member) { sum += item.price; }
        }
        return sum - discount;
    }
}

function render(a, b) {
    return a ? b : "{";
}
"""
    units = {unit.name: unit for unit in brace_units("Cart.java", source)}

    assert units["total"].parameters == 3
    assert units["total"].complexity == 4
    assert units["total"].lines == 7
    assert units["render"].parameters == 2
    assert "if" not in units and "for" not in units


def test_imports_resolve_to_repository_files():
    known = {"pkg/a.py", "pkg/b.py", "pkg/__init__.py", "web/app.js", "web/util/index.js"}

    assert import_targets("pkg/a.py", "from .b import x\nimport pkg\nimport os\n", "Python", known) == {"pkg/b.py", "pkg/__init__.py"}
    assert import_targets("web/app.js", "import u from './util';\nconst r = require('react');\n", "JavaScript", known) == {"web/util/index.js"}


def test_component_balance_inputs():
    assert component_of("src/orders/api.py") == "src/orders"
    assert component_of("backend/app.py") == "backend"
    assert component_of("setup.py") == "(root)"
    assert gini([10, 10, 10]) == 0
    assert gini([1, 1, 98]) > 0.6


def test_simple_units_rate_well_and_large_complex_units_rate_badly():
    file_lines = {"a/x.py": 400, "b/y.py": 400}
    small = [Unit("a/x.py", f"f{index}", index, 8, 2, 1) for index in range(50)]
    large = [Unit("a/x.py", f"g{index}", index, 120, 30, 8) for index in range(50)]

    good = maintainability_rating(small, file_lines, 0, {})
    bad = maintainability_rating(large, file_lines, 200, {})

    assert good["rating"] > 4.5
    assert bad["rating"] < 3
    assert good["properties"]["module_coupling"] is None
    assert bad["properties"]["unit_size"]["profile"]["very_high"] == 100.0


def test_repository_report_carries_the_rating(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("from app import util\n\ndef main(a):\n    return util.run(a)\n")
    (tmp_path / "app" / "util.py").write_text("def run(a):\n    if a:\n        return 1\n    return 0\n")
    (tmp_path / "web.js").write_text("function go(x) {\n  return x || 1;\n}\n")

    assert analyse_quality(tmp_path).maintainability()["units"] == 3

    report = scan_repository(tmp_path, {"name": "acme/app"})
    application, _ = application_from_report(report)

    assert 0.5 <= report["maintainability"]["rating"] <= 5.5
    assert application.repository["maintainability"] == report["maintainability"]
