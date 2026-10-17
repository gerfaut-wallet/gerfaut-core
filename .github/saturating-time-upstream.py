"""Fail when crates.io has a saturating-time release newer than the fork.

Run by .github/workflows/upstream.yml, from the repository root:

    REVIEWED=0.5.0 python3 .github/saturating-time-upstream.py

The fork's version is the one Cargo.lock records for the git source of
the [patch.crates-io] section. A release counts when it is not yanked,
not a pre-release, and newer than both the fork and REVIEWED, the newest
release already read and found without the fix.
"""

import json
import os
import sys
import time
import tomllib
import urllib.request

CRATE = "saturating-time"
FORK = "git+https://github.com/gerfaut-wallet/saturating-time"
API = f"https://crates.io/api/v1/crates/{CRATE}"
# crates.io asks every client to say who it is.
USER_AGENT = "gerfaut-core CI (https://github.com/gerfaut-wallet/gerfaut-core)"


def version(text):
    """The numeric fields of a release version, or None for a pre-release."""
    core, _, _ = text.partition("+")
    if "-" in core:
        return None
    fields = tuple(int(part) for part in core.split("."))
    return fields + (0,) * (3 - len(fields))


def fetch():
    request = urllib.request.Request(API, headers={"User-Agent": USER_AGENT})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except OSError as error:
            if attempt == 2:
                raise
            print(f"crates.io did not answer ({error}), trying again", file=sys.stderr)
            time.sleep(10)


def main():
    reviewed_text = os.environ.get("REVIEWED", "").strip()
    try:
        reviewed = version(reviewed_text)
    except ValueError:
        reviewed = None
    if reviewed is None:
        sys.exit("::error::REVIEWED must name a release, such as 0.5.0")

    with open("Cargo.lock", "rb") as lock:
        packages = tomllib.load(lock)["package"]
    forks = [
        package["version"]
        for package in packages
        if package["name"] == CRATE and package.get("source", "").startswith(FORK)
    ]
    if not forks:
        print(f"::warning::Cargo.lock no longer takes {CRATE} from the fork: this check has nothing left to watch")
        return
    fork = max(version(text) for text in forks)

    releases = [
        entry["num"]
        for entry in fetch()["versions"]
        if not entry["yanked"] and version(entry["num"]) is not None
    ]
    baseline = max(fork, reviewed)
    newer = sorted((text for text in releases if version(text) > baseline), key=version)
    fork_text = ".".join(map(str, fork))
    if newer:
        print(
            f"::error::{CRATE} {', '.join(newer)} on crates.io, newer than the fork ({fork_text}) "
            f"and than REVIEWED ({reviewed_text}): read its find_limit, then drop the fork "
            f"or raise REVIEWED in .github/workflows/upstream.yml"
        )
        sys.exit(1)
    latest = max(releases, key=version) if releases else "none"
    print(f"{CRATE}: newest release {latest}, fork {fork_text}, reviewed {reviewed_text}: nothing new")


if __name__ == "__main__":
    main()
