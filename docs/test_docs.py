# docs/test_docs.py
# LINxAI Phase 12 Documentation Test
#
# Run:
#   python3 docs/test_docs.py

import sys
from pathlib import Path


DOCS_DIR = Path(__file__).resolve().parent

REQUIRED_FILES = [
    "SRS.md",
    "SDS.md",
    "PHASE_STATUS.md",
    "README.md",
]

REQUIRED_SRS_TERMS = [
    "Software Requirements Specification",
    "Functional Requirements",
    "Non-Functional Requirements",
    "Acceptance Criteria",
    "LINxAI",
    "eBPF",
    "VPS",
    "Audit Logging",
]

REQUIRED_SDS_TERMS = [
    "Software Design Specification",
    "High-Level Architecture",
    "Module Design",
    "AI Engine",
    "Command Intelligence Engine",
    "Execution Controller",
    "eBPF Daemon",
    "Resource Manager",
    "VPS Manager",
    "Audit Logger",
]


def file_contains(path: Path, terms: list[str]) -> bool:
    if not path.exists():
        return False

    content = path.read_text(encoding="utf-8")

    return all(term in content for term in terms)


def run_tests():
    print("=" * 55)
    print("  LINxAI Phase 12 — Documentation Test")
    print("=" * 55)
    print()

    passed = 0
    total = 0

    def check(description, condition):
        nonlocal passed, total

        total += 1
        status = "✓" if condition else "✗"

        print(f"  [{status}] {description}")

        if condition:
            passed += 1

    check("Docs directory exists", DOCS_DIR.is_dir())

    for filename in REQUIRED_FILES:
        path = DOCS_DIR / filename

        check(f"{filename} exists", path.exists())
        check(f"{filename} is not empty", path.exists() and path.stat().st_size > 100)

    check(
        "SRS contains required sections",
        file_contains(DOCS_DIR / "SRS.md", REQUIRED_SRS_TERMS),
    )

    check(
        "SDS contains required sections",
        file_contains(DOCS_DIR / "SDS.md", REQUIRED_SDS_TERMS),
    )

    print()
    print("=" * 55)
    print(f"  RESULT: {passed}/{total} passed — {passed / total * 100:.0f}%")
    print(f"  Status: {'PASS ✓' if passed == total else 'PARTIAL'}")
    print("=" * 55)

    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)