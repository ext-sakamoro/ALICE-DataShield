#!/usr/bin/env python3
"""cargo test の出力を test target ごとに数え、0 本の target があれば失敗する

合計だけを見ると、1 つの target が 0 本 (cfg で全部外れた / filter で消えた) でも
他の target の件数で通ってしまう ⇒ `Running <target>` と `Doc-tests <crate>` の
区切りごとに `test result: … N passed` を読み、N = 0 の target を報告する

0 本が正しい target は scripts/test-count-allowlist.txt に「target 名 理由」で載せる
(理由の無い行は失敗) target が 1 つも読めない時も失敗する (比較 0 件を成功と読ませない)
cargo の出力は CARGO_TERM_COLOR=always で色の escape を含むので、読む前に除く

Usage: test_counts.py <cargo test の出力 file>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ALLOWLIST = HERE / "test-count-allowlist.txt"
ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[()*+][0-9A-Za-z]|\][^\x07\x1b]*(?:\x07|\x1b\\))")
HEADER_RE = re.compile(r"^\s*(?:Running\s+(?:unittests\s+)?(\S+)|Doc-tests\s+(\S+))")
RESULT_RE = re.compile(r"^test result: \w+\. (\d+) passed")


def target_name(path: str) -> str:
    """`tests/dp_bridge.rs` → `dp_bridge`, `src/lib.rs` → `lib`"""
    return Path(path.replace("\\", "/")).stem


def count(log: str) -> list[tuple[str, int]]:
    """(target, passed) in the order the targets ran"""
    out: list[tuple[str, int]] = []
    current: str | None = None
    for raw in ANSI_RE.sub("", log).splitlines():
        line = raw.strip()
        m = HEADER_RE.match(line)
        if m:
            current = target_name(m.group(1)) if m.group(1) else f"doc:{m.group(2)}"
            continue
        r = RESULT_RE.match(line)
        if r and current is not None:
            out.append((current, int(r.group(1))))
            current = None
    return out


def load_allowlist(path: Path = ALLOWLIST) -> tuple[dict[str, str], list[str]]:
    allowed: dict[str, str] = {}
    errors: list[str] = []
    if not path.exists():
        return allowed, errors
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        name, _, reason = line.strip().partition(" ")
        if not reason.strip():
            errors.append(f"{path.name}:{n}: `{name}` has no reason")
        allowed[name] = reason.strip()
    return allowed, errors


def check(log: str, allowed: dict[str, str]) -> tuple[list[str], list[tuple[str, int]]]:
    targets = count(log)
    errors: list[str] = []
    if not targets:
        errors.append("no test target found in the output (compared nothing)")
    for name, passed in targets:
        if passed == 0 and name not in allowed:
            errors.append(f"test target `{name}` ran 0 tests (list it in {ALLOWLIST.name} with a reason if that is intended)")
    return errors, targets


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(__doc__)
        return 2
    log = Path(args[0]).read_text(encoding="utf-8", errors="replace")
    allowed, errors = load_allowlist()
    more, targets = check(log, allowed)
    errors += more
    for e in errors:
        print(f"::error::{e}")
    print(f"test targets: {len(targets)}, tests passed: {sum(p for _, p in targets)}, "
          + ", ".join(f"{n}={p}" for n, p in targets))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
