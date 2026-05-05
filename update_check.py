"""Release version helpers and GitHub update checks for ``umadump``.

The update check is intentionally best-effort:

- it uses a short network timeout,
- treats GitHub/API failures as non-fatal,
- compares the embedded local version string against published GitHub release tags,
- and returns a ready-to-print notification payload when a newer release exists.

Automatic in-place updates are not implemented here because ``umadump`` may be run
either from source or as a bundled executable, which implies different upgrade flows.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from itertools import zip_longest
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

CURRENT_VERSION = "2.0.0-beta"
GITHUB_REPOSITORY = "Werseter/umadump"
RELEASES_API_URL = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/releases?per_page=20"
LATEST_RELEASE_PAGE_URL = f"https://github.com/{GITHUB_REPOSITORY}/releases/latest"
HTTP_USER_AGENT = f"umadump/{CURRENT_VERSION} (+https://github.com/{GITHUB_REPOSITORY})"
DEFAULT_TIMEOUT_SECONDS = 2.5

_VERSION_RE = re.compile(
    r"^v?(?P<release>\d+(?:\.\d+)*)(?:-(?P<prerelease>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ReleaseAsset:
    """Downloadable asset published with a GitHub release."""

    name: str
    browser_download_url: str


@dataclass(frozen=True)
class ReleaseInfo:
    """Normalized GitHub release metadata used by update notification logic."""

    tag_name: str
    html_url: str
    prerelease: bool
    assets: tuple[ReleaseAsset, ...]


@dataclass(frozen=True)
class UpdateCheckResult:
    """Describes a newer release discovered for the current local build."""

    current_version: str
    latest_version: str
    release_page_url: str
    download_url: str


@dataclass(frozen=True)
class ParsedVersion:
    """Comparable SemVer-like version data extracted from a tag string."""

    release_parts: tuple[int, ...]
    prerelease_parts: tuple[str, ...]

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease_parts)


def _parse_version(version: str) -> Optional[ParsedVersion]:
    """Parse a small subset of SemVer-like Git tags used by GitHub releases.

    Returns ``ParsedVersion`` or ``None`` when the value cannot be compared safely.
    """

    normalized = version.strip()
    match = _VERSION_RE.fullmatch(normalized)
    if not match:
        return None

    release_parts = tuple(int(part) for part in match.group("release").split("."))
    prerelease = match.group("prerelease")
    prerelease_parts = tuple(part.lower() for part in prerelease.split(".")) if prerelease else ()
    return ParsedVersion(release_parts=release_parts, prerelease_parts=prerelease_parts)


def _compare_identifiers(left: str, right: str) -> int:
    """Compare two prerelease identifiers using SemVer precedence rules."""

    left_is_numeric = left.isdigit()
    right_is_numeric = right.isdigit()
    if left_is_numeric and right_is_numeric:
        left_value = int(left)
        right_value = int(right)
        return (left_value > right_value) - (left_value < right_value)
    if left_is_numeric != right_is_numeric:
        return -1 if left_is_numeric else 1
    return (left > right) - (left < right)


def compare_versions(candidate_version: str, current_version: str) -> int:
    """Compare two SemVer-like version strings.

    Returns ``1`` when ``candidate_version`` is newer, ``-1`` when it is older,
    and ``0`` when equal or when either version cannot be compared safely.
    """

    candidate = _parse_version(candidate_version)
    current = _parse_version(current_version)
    if candidate is None or current is None:
        return 0

    width = max(len(candidate.release_parts), len(current.release_parts))
    padded_candidate = candidate.release_parts + (0,) * (width - len(candidate.release_parts))
    padded_current = current.release_parts + (0,) * (width - len(current.release_parts))
    if padded_candidate != padded_current:
        return (padded_candidate > padded_current) - (padded_candidate < padded_current)

    if candidate.is_prerelease != current.is_prerelease:
        return -1 if candidate.is_prerelease else 1

    for left, right in zip_longest(candidate.prerelease_parts, current.prerelease_parts, fillvalue=None):
        if left is None:
            return -1
        if right is None:
            return 1
        part_result = _compare_identifiers(left, right)
        if part_result:
            return part_result
    return 0


def is_newer_version(candidate_version: str, current_version: str) -> bool:
    """Return whether ``candidate_version`` is newer than ``current_version``."""

    return compare_versions(candidate_version, current_version) > 0


def _release_assets_from_payload(payload: dict[str, object]) -> tuple[ReleaseAsset, ...]:
    """Extract typed asset metadata from a GitHub release payload."""

    assets_raw = payload.get("assets")
    if not isinstance(assets_raw, list):
        return ()

    assets: list[ReleaseAsset] = []
    for asset in assets_raw:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name")
        browser_download_url = asset.get("browser_download_url")
        if isinstance(name, str) and isinstance(browser_download_url, str):
            assets.append(ReleaseAsset(name=name, browser_download_url=browser_download_url))
    return tuple(assets)


def _release_info_from_payload(payload: dict[str, object]) -> Optional[ReleaseInfo]:
    """Parse a single GitHub release object into ``ReleaseInfo``."""

    if payload.get("draft") is True:
        return None

    tag_name = payload.get("tag_name")
    html_url = payload.get("html_url")
    prerelease = payload.get("prerelease")
    if not isinstance(tag_name, str) or not isinstance(html_url, str) or not isinstance(prerelease, bool):
        return None

    return ReleaseInfo(
        tag_name=tag_name,
        html_url=html_url,
        prerelease=prerelease,
        assets=_release_assets_from_payload(payload),
    )


def fetch_available_releases(timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> tuple[ReleaseInfo, ...]:
    """Fetch published GitHub releases, including prereleases, returning an empty tuple on failure."""

    request = Request(
        RELEASES_API_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": HTTP_USER_AGENT,
        },
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return ()

    if not isinstance(payload, list):
        return ()

    releases: list[ReleaseInfo] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        release = _release_info_from_payload(item)
        if release is not None:
            releases.append(release)
    return tuple(releases)


def _allow_prerelease_updates(current_version: str) -> bool:
    """Return whether the current build should consider prerelease GitHub releases."""

    parsed = _parse_version(current_version)
    return parsed is not None and parsed.is_prerelease


def select_newer_release(current_version: str, releases: tuple[ReleaseInfo, ...]) -> Optional[ReleaseInfo]:
    """Pick the newest applicable release for the current build channel.

    Stable builds only consider stable releases. Prerelease builds consider both
    newer prereleases and newer stable releases.
    """

    allow_prereleases = _allow_prerelease_updates(current_version)
    newest: Optional[ReleaseInfo] = None
    for release in releases:
        if release.prerelease and not allow_prereleases:
            continue
        if not is_newer_version(release.tag_name, current_version):
            continue
        if newest is None or compare_versions(release.tag_name, newest.tag_name) > 0:
            newest = release
    return newest


def fetch_latest_release(current_version: str = CURRENT_VERSION,
                         timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> Optional[ReleaseInfo]:
    """Fetch the newest applicable GitHub release for the current build version."""

    return select_newer_release(current_version, fetch_available_releases(timeout_seconds=timeout_seconds))


def _select_download_url(release: ReleaseInfo) -> str:
    """Pick the most useful update link for the current runtime form."""

    if getattr(sys, "frozen", False):
        for asset in release.assets:
            if asset.name.lower().endswith(".exe"):
                return asset.browser_download_url
        if release.assets:
            return release.assets[0].browser_download_url
    return release.html_url


def check_for_updates(current_version: str = CURRENT_VERSION) -> Optional[UpdateCheckResult]:
    """Compare the embedded version string against applicable GitHub releases."""

    release = fetch_latest_release(current_version=current_version)
    if release is None:
        return None

    return UpdateCheckResult(
        current_version=current_version,
        latest_version=release.tag_name,
        release_page_url=release.html_url,
        download_url=_select_download_url(release),
    )


def notify_if_update_available(current_version: str = CURRENT_VERSION) -> None:
    """Print a startup notice when a newer GitHub release is available."""

    update = check_for_updates(current_version=current_version)
    if update is None:
        return

    print()
    print("=" * 72)
    print(f"Update available: {update.latest_version} (current: {update.current_version})")
    print(f"Release page: {update.release_page_url}")
    if update.download_url != update.release_page_url:
        print(f"Direct download: {update.download_url}")
    print("=" * 72)
    print()
