"""Fail when crates.io has a saturating-time release nobody has read yet.

Run by .github/workflows/upstream.yml, from the repository root:

    REVIEWED="0.5.0" python3 .github/saturating-time-upstream.py

The fork's version is the one Cargo.lock records for the git source of
the [patch.crates-io] section. A release counts when it is not yanked,
not a pre-release, newer than the fork, and missing from REVIEWED, the
space-separated releases already read and found without the fix. A list
rather than a ceiling: a fixed 0.4.x published after 0.5.0 still counts.

Any failure, including a fork that is no longer in Cargo.lock, exits
non-zero, so that the scheduled run reports it instead of going quiet.
"""

import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.request

try:
    import tomllib
except ImportError:
    sys.exit("::error::this check needs Python 3.11 or later, for tomllib")

CRATE = "saturating-time"
FORK = "git+https://github.com/gerfaut-wallet/saturating-time"
API = f"https://crates.io/api/v1/crates/{CRATE}/versions"
# crates.io asks every client to say who it is.
USER_AGENT = "gerfaut-core CI (https://github.com/gerfaut-wallet/gerfaut-core)"


def numbers(text):
    """The major, minor and patch numbers of a version, or None."""
    core = text.partition("+")[0].partition("-")[0]
    try:
        fields = tuple(int(part) for part in core.split("."))
    except ValueError:
        return None
    if not 1 <= len(fields) <= 3:
        return None
    return fields + (0,) * (3 - len(fields))


def is_release(text):
    """A version without a pre-release part, such as 0.5.0 but not 0.6.0-rc.1."""
    return "-" not in text.partition("+")[0] and numbers(text) is not None


def show(fields):
    return ".".join(map(str, fields))


def fetch():
    """Every published version of the crate, as crates.io lists them."""
    versions, url = [], f"{API}?per_page=100"
    while url:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    page = json.load(response)
                break
            except urllib.error.HTTPError as error:
                if error.code != 429 and error.code < 500 or attempt == 2:
                    raise
                print(f"crates.io: {error}, trying again", file=sys.stderr)
            except (OSError, ValueError, http.client.HTTPException) as error:
                if attempt == 2:
                    raise
                print(f"crates.io: {error}, trying again", file=sys.stderr)
            time.sleep(10)
        versions += page["versions"]
        following = (page.get("meta") or {}).get("next_page")
        url = f"{API}{following}" if following else None
    return versions


def main():
    reviewed_texts = os.environ.get("REVIEWED", "").split()
    reviewed = {numbers(text) for text in reviewed_texts}
    if not reviewed_texts or None in reviewed:
        sys.exit("::error::REVIEWED must list releases, such as 0.5.0, separated by spaces")

    with open("Cargo.lock", "rb") as lock:
        cargo_lock = tomllib.load(lock)
    forks = [
        package["version"]
        for package in cargo_lock.get("package", [])
        if package["name"] == CRATE and package.get("source", "").startswith(FORK)
    ]
    if not forks:
        unused = [
            package
            for package in (cargo_lock.get("patch") or {}).get("unused", [])
            if package.get("name") == CRATE
        ]
        if unused:
            sys.exit(
                f"::error::the [patch.crates-io] fork of {CRATE} no longer applies "
                f"(Cargo.lock lists it under [[patch.unused]]): the Windows fix is off"
            )
        sys.exit(
            f"::error::Cargo.lock no longer takes {CRATE} from the fork: if the fork is gone "
            f"on purpose, remove .github/workflows/upstream.yml and this script"
        )
    fork = max(numbers(text) for text in forks)

    releases = {
        numbers(entry["num"])
        for entry in fetch()
        if not entry.get("yanked") and is_release(entry.get("num", ""))
    }
    unread = sorted(release for release in releases if release > fork and release not in reviewed)
    if unread:
        print(
            f"::error::{CRATE} {', '.join(map(show, unread))} on crates.io, newer than the fork "
            f"({show(fork)}) and not in REVIEWED: read its find_limit, then drop the fork "
            f"or add the release to REVIEWED in .github/workflows/upstream.yml"
        )
        sys.exit(1)
    latest = show(max(releases)) if releases else "none"
    print(f"{CRATE}: newest release {latest}, fork {show(fork)}, reviewed {' '.join(reviewed_texts)}: nothing new")


if __name__ == "__main__":
    main()
