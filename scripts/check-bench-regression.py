#!/usr/bin/env python3
"""09.4: fail if any criterion bench regressed by more than 15% against
the restored baseline.

Criterion already does its own significance testing (p < 0.05) and
prints an explicit verdict per benchmark function; this just adds the
magnitude gate the spec asks for on top of that. Reads one or more
captured `cargo bench` stdout logs (each block looks like)::

                 change:
                        time:   [-2.60% -2.31% -2.02%] (p = 0.01 < 0.05)
                        thrpt:  [+2.07% +2.37% +2.66%]
                        Performance has regressed.

and flags any "Performance has regressed." verdict whose point-estimate
(the middle of the three time-change percentages) exceeds the
threshold.
"""

import re
import sys

THRESHOLD_PCT = 15.0
CHANGE_RE = re.compile(r"^\s*change:\s*$")
# Criterion prints U+2212 MINUS SIGN for negative percentages, not ASCII
# hyphen-minus — both must match or every "improved" line (all three
# values negative) silently fails to parse.
SIGN = r"[+\-−]"
TIME_RE = re.compile(
    rf"^\s*time:\s*\[\s*({SIGN}[0-9.]+)%\s+({SIGN}[0-9.]+)%\s+({SIGN}[0-9.]+)%\s*\]"
)
VERDICT_RE = re.compile(
    r"Performance has (regressed|improved)\.|No change in performance detected\.|Change within noise threshold\."
)


def scan(path: str) -> list[str]:
    failures = []
    in_change = False
    pending_pct = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if CHANGE_RE.match(line):
                in_change = True
                pending_pct = None
                continue
            if not in_change:
                continue
            m = TIME_RE.match(line)
            if m:
                pending_pct = float(m.group(2).replace("−", "-"))  # point estimate
                continue
            if "Performance has regressed." in line:
                magnitude = abs(pending_pct) if pending_pct is not None else 0.0
                if magnitude > THRESHOLD_PCT:
                    failures.append(
                        f"{path}: regression of {magnitude:.2f}% exceeds the "
                        f"{THRESHOLD_PCT:.0f}% gate"
                    )
                in_change = False
            elif VERDICT_RE.search(line):
                in_change = False
    return failures


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: check-bench-regression.py <log> [<log> ...]", file=sys.stderr)
        return 2
    all_failures = []
    for path in argv:
        all_failures.extend(scan(path))
    for failure in all_failures:
        print(f"::error::{failure}")
    if not all_failures:
        print(f"no bench regressed by more than {THRESHOLD_PCT:.0f}%")
    return 1 if all_failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
