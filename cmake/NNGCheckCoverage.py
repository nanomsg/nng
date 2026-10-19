#!/usr/bin/env python3
#
# Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

"""Reject LCOV reports that omit execution data for required source files."""

import argparse
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("sources", nargs="+")
    args = parser.parse_args()
    sources = {source.replace("\\", "/"): {} for source in args.sources}
    current = None
    for line in args.report.read_text(encoding="utf-8").splitlines():
        if line.startswith("SF:"):
            path = line[3:].replace("\\", "/")
            current = next(
                (
                    source
                    for source in sources
                    if path == source or path.endswith("/" + source)
                ),
                None,
            )
        elif line.startswith("DA:") and current is not None:
            number, count, *_ = line[3:].split(",")
            lines = sources[current]
            lines[number] = lines.get(number, False) or int(count) > 0
        elif line == "end_of_record":
            current = None

    failed = False
    for source, lines in sources.items():
        covered = sum(lines.values())
        if not lines:
            print(f"ERROR: {source} is missing line coverage data")
            failed = True
        elif not covered:
            print(f"ERROR: {source} has no executed lines")
            failed = True
        else:
            print(f"{source}: {covered}/{len(lines)} lines covered")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
