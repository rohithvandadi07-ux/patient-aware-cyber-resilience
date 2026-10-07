#!/usr/bin/env python3
"""Download CICIoMT2024's extracted flow-feature CSVs.

Written to run on a machine with normal internet access -- this project's own
development sandbox has network egress restricted to a small allowlist and
cannot reach `cicresearch.ca`, so this script has not been executed as part of
building this repository (see datasets/LICENSE_NOTES.md). Nothing in this repo
claims CICIoMT2024 was actually used until this script has been run for real
and that file's status line is updated.

Before running this: open https://www.unb.ca/cic/datasets/iomt-dataset-2024.html
and confirm you accept CIC's license terms. CIC's standard terms require
citing the originating paper and do not permit redistributing the raw dataset.

The dataset's real folder structure (per the official page, confirmed by
research but not independently crawled from this sandbox -- see
datasets/LICENSE_NOTES.md for how that was checked):

    http://cicresearch.ca/IOTDataset/CICIoMT2024/
    |-- Bluetooth/
    |   |-- attacks/        (benign + attack .pcap, split into test/ and train/)
    |   `-- profiling/      (profiling .pcap from power experiments)
    `-- WiFi_and_MQTT/
        |-- attacks/        (benign + attack .pcap, test/train splits, plus a
        |                     csv/ subdirectory with pre-extracted features)
        `-- profiling/      (profiling .pcap, with a csv/ subdirectory)

This script deliberately does NOT hardcode a guessed list of per-attack CSV
filenames -- CIC's exact naming (casing, separators) was not independently
confirmed, and the download page may be a click-through/terms form rather than
a bare Apache listing (CIC uses that pattern for other datasets of theirs, e.g.
SBAN). Instead, it crawls whatever index the server returns at the WiFi/MQTT
csv/ paths and downloads every CSV link it finds there. If the server returns a
form instead of a listing, the script says so and stops -- it does not attempt
to script around a consent page.

Usage:
    python download_ciciomt2024.py --output datasets/raw/ciciomt2024/
    python download_ciciomt2024.py --output datasets/raw/ciciomt2024/ --dry-run
"""

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import urljoin

BASE_URL = "http://cicresearch.ca/IOTDataset/CICIoMT2024/"

# The two csv/ subdirectories under WiFi_and_MQTT that hold pre-extracted,
# ready-to-train flow features (as opposed to raw .pcap, which would still
# need feature extraction before this project's training pipeline could use
# it -- out of scope for this script).
CSV_INDEX_PATHS = [
    "WiFi_and_MQTT/attacks/csv/",
    "WiFi_and_MQTT/profiling/csv/",
]

CSV_LINK_PATTERN = re.compile(r'href="([^"]+\.csv)"', re.IGNORECASE)


def _discover_csv_urls(session, index_url: str) -> list[str]:
    """Fetch an index page and extract every .csv link it lists.

    Returns an empty list (with a printed warning) rather than raising, if the
    page doesn't look like a directory listing -- e.g. if CIC is serving a
    terms/consent form instead, which this script will not try to script
    around.
    """
    response = session.get(index_url, timeout=30)
    response.raise_for_status()

    matches = CSV_LINK_PATTERN.findall(response.text)
    if not matches:
        print(
            f"  WARNING: no .csv links found at {index_url}. This may mean the page "
            "is a consent/terms form rather than a file listing -- open it in a "
            "browser, accept any terms manually, and re-check this script's "
            "assumptions before relying on it further.",
            file=sys.stderr,
        )
        return []

    return [urljoin(index_url, match) for match in matches]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="Directory to download CSVs into."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Discover and list available CSV files without downloading them.",
    )
    args = parser.parse_args()

    print("CICIoMT2024 dataset page: https://www.unb.ca/cic/datasets/iomt-dataset-2024.html")
    print(f"Download host: {BASE_URL}")
    print(
        "Before proceeding, confirm you have read and accept CIC's license terms "
        "on the dataset page above.\n"
    )

    try:
        import requests
    except ImportError:
        print(
            "This script needs the 'requests' package. Install it with:\n"
            "    pip install requests\n"
            "(not a project dependency -- this script runs standalone, outside "
            "the backend's own virtual environment, on whatever machine has "
            "network access to CIC's servers.)",
            file=sys.stderr,
        )
        return 1

    session = requests.Session()
    all_csv_urls: list[str] = []

    for relative_path in CSV_INDEX_PATHS:
        index_url = urljoin(BASE_URL, relative_path)
        print(f"Checking index: {index_url}")
        try:
            csv_urls = _discover_csv_urls(session, index_url)
        except requests.RequestException as exc:
            print(f"  ERROR: could not reach {index_url}: {exc}", file=sys.stderr)
            continue

        print(f"  found {len(csv_urls)} CSV file(s)")
        all_csv_urls.extend(csv_urls)

    if not all_csv_urls:
        print(
            "\nNo CSV files discovered. Either the paths above have changed, or "
            "the server is gating access behind a form rather than serving a "
            "plain directory listing -- check manually in a browser before "
            "editing CSV_INDEX_PATHS above.",
            file=sys.stderr,
        )
        return 1

    if args.dry_run:
        print(f"\nDry run -- would download {len(all_csv_urls)} file(s):")
        for url in all_csv_urls:
            print(f"  - {url}")
        return 0

    args.output.mkdir(parents=True, exist_ok=True)
    for url in all_csv_urls:
        filename = url.rsplit("/", maxsplit=1)[-1]
        dest = args.output / filename
        print(f"Downloading {filename} ...")
        response = session.get(url, timeout=120)
        response.raise_for_status()
        dest.write_bytes(response.content)

    print(f"\nDownloaded {len(all_csv_urls)} file(s) to {args.output}")
    print(
        "Next: update datasets/LICENSE_NOTES.md's CICIoMT2024 status line with "
        "today's date, then point app/cybersecurity/training.py at this "
        "directory instead of the synthetic stand-in data."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
