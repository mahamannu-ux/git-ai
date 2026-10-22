#!/usr/bin/env python3
"""Select a deterministic eligible fork release pair for the MDM regression.

Adapted from git-ai-project/git-ai@0cd8ede139e5cb5287cd09563ce677525d703547:
the fork uses the immediate N-1 release, requires TrackAI package assets and
production trust pins, and reports an unavailable pair as not run.
"""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path
from typing import Any

SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
REQUIRED_ASSETS = {
    "trackai-endpoint-macos-arm64.pkg",
    "trackai-endpoint-macos-x64.pkg",
    "git-ai-windows-x64.msi",
    "git-ai-login-start-macos.sh",
    "git-ai-login-start-windows.ps1",
    "install.sh",
    "install.ps1",
    "PKG-SHA256SUMS",
    "SHA256SUMS",
}


def asset_names(release: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for asset in release.get("assets", []):
        name = asset.get("name") if isinstance(asset, dict) else asset
        if isinstance(name, str):
            names.add(name)
    return names


def select_pair(
    releases: list[dict[str, Any]], trusted_tags: set[str]
) -> tuple[str, str] | None:
    eligible: dict[tuple[int, int, int], str] = {}
    for release in releases:
        tag = release.get("tag_name")
        match = SEMVER.fullmatch(tag) if isinstance(tag, str) else None
        production_trust_pinned = tag in trusted_tags if isinstance(tag, str) else False
        if (
            match is None
            or release.get("draft", False)
            or release.get("prerelease", False)
            or not production_trust_pinned
            or not REQUIRED_ASSETS.issubset(asset_names(release))
        ):
            continue
        version = tuple(int(part) for part in match.groups())
        if version in eligible and eligible[version] != tag:
            raise ValueError(f"ambiguous release tags for {version}")
        eligible[version] = tag

    ordered = sorted(eligible)
    if len(ordered) < 2:
        return None
    return eligible[ordered[-2]], eligible[ordered[-1]]


def emit(pair: tuple[str, str] | None, output: Path | None) -> None:
    if pair is None:
        values = ["pair_available=false", "older=", "latest="]
        print("no eligible release pair")
    else:
        older, latest = pair
        values = ["pair_available=true", f"older={older}", f"latest={latest}"]
        print(f"eligible release pair: {older} -> {latest}")
    if output is not None:
        with output.open("a", encoding="utf-8") as handle:
            for value in values:
                handle.write(f"{value}\n")


def release(tag: str, *, assets: set[str] | None = None, **fields: Any) -> dict[str, Any]:
    return {
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "assets": [{"name": name} for name in sorted(assets or REQUIRED_ASSETS)],
        **fields,
    }


def self_test() -> None:
    assert select_pair([], set()) is None
    assert select_pair([release("v1.6.19")], {"v1.6.19"}) is None
    pair = select_pair(
        [
            release("v1.6.18"),
            release("v1.6.20"),
            release("v1.6.19"),
            release("v9.9.9", prerelease=True),
            release("v8.8.8", draft=True),
            release("v7.7.7", assets=REQUIRED_ASSETS - {"SHA256SUMS"}),
            release("v6.6.6"),
        ],
        {"v1.6.18", "v1.6.19", "v1.6.20", "v7.7.7", "v8.8.8", "v9.9.9"},
    )
    assert pair == ("v1.6.19", "v1.6.20")
    assert select_pair([release("v1.6.19"), release("v1.6.20")], set()) is None
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "output"
        emit(None, output)
        assert output.read_text(encoding="utf-8").splitlines() == [
            "pair_available=false",
            "older=",
            "latest=",
        ]
    print("fixture_release_selection=yes")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--releases-json", type=Path)
    parser.add_argument("--trusted-tags", type=Path)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return
    if args.releases_json is None or args.trusted_tags is None:
        parser.error("--releases-json and --trusted-tags are required")
    releases = json.loads(args.releases_json.read_text(encoding="utf-8"))
    if not isinstance(releases, list):
        raise SystemExit("release API response must be an array")
    trusted_tags = {
        line.strip()
        for line in args.trusted_tags.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    emit(select_pair(releases, trusted_tags), args.github_output)


if __name__ == "__main__":
    main()
