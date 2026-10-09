from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(ROOT)
    )


from backend.platforms.mendix import (
    MendixModelParser,
    MendixSecurityAnalyzer,
)


MODEL_FILE = ROOT / "model.json"


def _print_statistics(statistics):
    print()
    print("MODEL STATISTICS")
    print("-" * 60)
    for key, value in statistics.items():
        print(f"{key:25} {value}")


def _print_findings(findings):
    print()
    print("SECURITY ANALYSIS")
    print("-" * 60)
    print(f"Findings: {len(findings)}")
    for finding in findings[:20]:
        print()
        print(f"[{finding['severity'].upper()}] {finding['rule_id']}")
        print(finding["title"])
        print(f"Entity: {finding['entity']}")
        print(f"Recommendation: {finding['recommendation']}")


def main():
    print()
    print("=" * 60)
    print("MENDIX MODEL ANALYSIS")
    print("=" * 60)

    print(
        f"Model file: {MODEL_FILE}"
    )

    if not MODEL_FILE.exists():

        print(
            "ERROR: model.json was not found."
        )

        print(
            "Place the successful dump-mpr output "
            "at the project root."
        )

        return 1

    print()
    print("Parsing model...")

    parser = MendixModelParser.from_file(
        MODEL_FILE
    )

    model = parser.parse()
    _print_statistics(model.statistics())
    analyzer = MendixSecurityAnalyzer(
        model
    )
    findings = analyzer.analyze()
    _print_findings(findings)
    print()
    print("=" * 60)

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )