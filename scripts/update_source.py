#!/usr/bin/env python3
"""Build AltStore Classic / SideStore / Feather sources from public release IPAs.

Only reads ZIP metadata and executable signature data. Never executes an IPA.
Requires Python 3.11+, no third-party dependencies.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import struct
import tempfile
import urllib.request
import zipfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CACHE_VERSION = 1
MAX_IPA = 2 * 1024**3
MAX_BINARY = 512 * 1024**2


def require(condition, message):
    if not condition:
        raise ValueError(message)


def json_get(url):
    headers = {"User-Agent": "23aces-ipa-source", "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        return json.load(response)


def fetch_releases(repo):
    require(re.fullmatch(r"[\w.-]+/[\w.-]+", repo), "Invalid release repository")
    releases = []
    for page in range(1, 101):
        batch = json_get(f"https://api.github.com/repos/{repo}/releases?per_page=100&page={page}")
        require(isinstance(batch, list), "GitHub returned an invalid release list")
        releases.extend(batch)
        if len(batch) < 100:
            return releases
    raise ValueError("More than 10,000 releases; refusing to publish an incomplete source")


def signature_entitlements(blob):
    """Read Apple's embedded-signature SuperBlob and XML entitlements blob."""
    require(len(blob) >= 12, "Truncated code signature")
    magic, length, count = struct.unpack_from(">III", blob)
    require(magic == 0xFADE0CC0 and length <= len(blob), "Invalid embedded code signature")
    require(12 + 8 * count <= length, "Invalid signature index")
    keys, xml, der = set(), False, False
    for index in range(count):
        _, offset = struct.unpack_from(">II", blob, 12 + index * 8)
        require(offset + 8 <= length, "Signature blob offset out of bounds")
        kind, size = struct.unpack_from(">II", blob, offset)
        require(size >= 8 and offset + size <= length, "Signature blob size out of bounds")
        if kind == 0xFADE7171:
            value = plistlib.loads(blob[offset + 8:offset + size].rstrip(b"\0"))
            require(isinstance(value, dict), "Invalid entitlements plist")
            keys.update(value)
            xml = True
        elif kind == 0xFADE7172:
            der = True
    require(not der or xml, "DER-only entitlements need a metadata reader update; keeping the previous feed")
    return keys


def macho_entitlements(data):
    """Read signatures from thin or universal Mach-O files with bounds checks."""
    require(len(data) >= 4, "Truncated executable")
    magic = data[:4]
    fat_formats = {
        b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\xfe\xca": ("<", True),
    }
    if magic in fat_formats:
        endian, wide = fat_formats[magic]
        require(len(data) >= 8, "Truncated universal header")
        count = struct.unpack_from(endian + "I", data, 4)[0]
        stride = 32 if wide else 20
        require(0 < count <= 64 and 8 + stride * count <= len(data), "Invalid universal header")
        keys = set()
        for i in range(count):
            offset, size = struct.unpack_from(endian + ("QQ" if wide else "II"), data, 8 + stride * i + 8)
            require(size >= 4 and offset >= 8 + stride * count and offset + size <= len(data), "Invalid architecture range")
            require(data[offset:offset + 4] not in fat_formats, "Nested universal executable")
            keys.update(macho_entitlements(data[offset:offset + size]))
        return keys
    formats = {
        b"\xce\xfa\xed\xfe": ("<", 28), b"\xcf\xfa\xed\xfe": ("<", 32),
        b"\xfe\xed\xfa\xce": (">", 28), b"\xfe\xed\xfa\xcf": (">", 32),
    }
    require(magic in formats, "Unsupported executable format")
    endian, cursor = formats[magic]
    require(len(data) >= cursor, "Truncated Mach-O header")
    count, command_size = struct.unpack_from(endian + "II", data, 16)
    end = cursor + command_size
    require(end <= len(data) and count <= command_size // 8, "Invalid load command table")
    keys = set()
    for _ in range(count):
        require(cursor + 8 <= end, "Truncated load command")
        command, size = struct.unpack_from(endian + "II", data, cursor)
        require(size >= 8 and cursor + size <= end, "Invalid load command")
        if command == 0x1D:  # LC_CODE_SIGNATURE
            require(size >= 16, "Invalid signature command")
            offset, length = struct.unpack_from(endian + "II", data, cursor + 8)
            require(offset + length <= len(data), "Code signature is out of bounds")
            keys.update(signature_entitlements(data[offset:offset + length]))
        cursor += size
    return keys


def read_member(archive, path, limit):
    member = archive.getinfo(path)
    require(member.file_size <= limit, f"ZIP member too large: {path}")
    with archive.open(member) as stream:
        value = stream.read(limit + 1)
    require(len(value) <= limit, f"ZIP member exceeded limit: {path}")
    return value


def inspect_ipa(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "Duplicate ZIP member names")
        mains = [name for name in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)]
        require(len(mains) == 1, "Expected exactly one main Payload app")
        main = plistlib.loads(read_member(archive, mains[0], 4 * 1024**2))
        for key in ("CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion"):
            require(isinstance(main.get(key), str) and main[key], f"Missing {key}; will not guess from release tag")
        root = mains[0].rsplit("/", 1)[0] + "/"
        bundles = [name for name in names if name.startswith(root) and name.endswith((".app/Info.plist", ".appex/Info.plist"))]
        keys, privacy = set(), {}
        for name in sorted(bundles):
            info = plistlib.loads(read_member(archive, name, 4 * 1024**2))
            privacy.update({k: v for k, v in info.items() if "UsageDescription" in k and isinstance(v, str)})
            executable = info.get("CFBundleExecutable")
            require(isinstance(executable, str) and executable and "/" not in executable and executable not in (".", ".."), "Invalid bundle executable")
            binary = name.rsplit("/", 1)[0] + "/" + executable
            keys.update(macho_entitlements(read_member(archive, binary, MAX_BINARY)))
        return {
            "name": main.get("CFBundleDisplayName") or main.get("CFBundleName") or main["CFBundleIdentifier"],
            "bundleIdentifier": main["CFBundleIdentifier"],
            "version": main["CFBundleShortVersionString"],
            "buildVersion": main["CFBundleVersion"],
            "minOSVersion": main.get("MinimumOSVersion"),
            "appPermissions": {"entitlements": sorted(keys), "privacy": dict(sorted(privacy.items()))},
        }


def verify_asset(path, asset):
    require(path.stat().st_size == asset["size"], f"Incorrect file size for {asset['name']}")
    expected = asset.get("digest")
    if expected:
        require(expected.startswith("sha256:"), "Unsupported asset digest")
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        require(actual == expected.split(":", 1)[1], f"Checksum mismatch for {asset['name']}")


def get_metadata(asset, repo, local_dir=None):
    require(0 < asset["size"] <= MAX_IPA, "IPA exceeds the 2 GiB download limit")
    require(asset["browser_download_url"].startswith(f"https://github.com/{repo}/releases/download/"), "Unexpected IPA download origin")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(local_dir) / f"{asset['id']}.ipa" if local_dir else Path(directory) / "app.ipa"
        if not local_dir:
            # Public asset request: never send the Actions token to a download redirect.
            request = urllib.request.Request(asset["browser_download_url"], headers={"User-Agent": "23aces-ipa-source"})
            total = 0
            with urllib.request.urlopen(request, timeout=120) as response, path.open("wb") as output:
                while chunk := response.read(1024**2):
                    total += len(chunk)
                    require(total <= asset["size"] and total <= MAX_IPA, "Download exceeds declared size")
                    output.write(chunk)
        verify_asset(path, asset)
        return inspect_ipa(path)


def select_assets(releases, include_prereleases):
    selected = []
    for release in releases:
        if release.get("draft") or (release.get("prerelease") and not include_prereleases):
            continue
        for asset in release.get("assets", []):
            if asset.get("state") == "uploaded" and asset["name"].lower().endswith(".ipa"):
                selected.append((release, asset))
    # Publication order is intentional: tags may belong to unrelated apps.
    selected.sort(key=lambda pair: (pair[0]["published_at"], pair[1]["updated_at"], pair[1]["id"]), reverse=True)
    return selected


def make_app(records, config):
    latest = records[0]
    meta = latest["metadata"]
    app = {
        "name": meta["name"], "bundleIdentifier": meta["bundleIdentifier"],
        "developerName": f"Published by {config['releasesRepository'].split('/')[0]}",
        "localizedDescription": f"{meta['name']} from {config['releasesRepository']} releases.\nLatest file: {latest['assetName']}",
        "iconURL": config["iconURL"], "versions": [],
    }
    override = config.get("apps", {}).get(meta["bundleIdentifier"], {})
    for key in ("name", "developerName", "localizedDescription", "iconURL"):
        if key in override:
            app[key] = override[key]
    seen, entitlements, privacy = set(), set(), {}
    for record in records:
        info = record["metadata"]
        identity = (info["version"], info["buildVersion"])
        if identity in seen:
            continue
        seen.add(identity)
        version = {key: info[key] for key in ("version", "buildVersion")}
        version.update(date=record["date"], downloadURL=record["downloadURL"], size=record["size"], localizedDescription=record["description"])
        if info.get("minOSVersion"):
            version["minOSVersion"] = info["minOSVersion"]
        app["versions"].append(version)
        entitlements.update(info["appPermissions"]["entitlements"])
        for key, value in info["appPermissions"]["privacy"].items():
            privacy.setdefault(key, value)
    app["appPermissions"] = {"entitlements": sorted(entitlements), "privacy": dict(sorted(privacy.items()))}
    first = app["versions"][0]
    app.update(version=first["version"], versionDate=first["date"], versionDescription=first["localizedDescription"], downloadURL=first["downloadURL"], size=first["size"])
    return app


def make_mod_app(record, config):
    """Each release asset is a separate mod, even with an identical bundle/version."""
    app = make_app([record], config)
    fallback = f"{Path(record['assetName']).stem} (release {record['releaseTag']})"
    app["name"] = config.get("assetNames", {}).get(str(record["assetId"]), fallback)
    app["subtitle"] = record["assetName"]
    app["localizedDescription"] = (
        f"Mod: {app['name']}\nFile: {record['assetName']}\n"
        f"Release: {record['releaseTag']}\n\n{record['description']}"
    )
    return app


def make_source(config, apps, suffix="", title=None, filename=None):
    filename = filename or (f"sources/{suffix}.json" if suffix else "source.json")
    return {
        "name": title or config["name"], "identifier": config["identifier"] + ("." + suffix if suffix else ""),
        "subtitle": config["subtitle"], "description": "Published IPA assets from GitHub Releases. Refreshed by GitHub Actions.",
        "sourceURL": f"https://raw.githubusercontent.com/{config['sourceRepository']}/{config['branch']}/{filename}",
        "iconURL": config["iconURL"], "website": f"https://github.com/{config['releasesRepository']}/releases",
        "apps": apps, "news": [],
    }


def validate_source(source, feather=False):
    require(source.get("name") and source.get("identifier"), "Missing source identity")
    ids = set()
    for app in source["apps"]:
        # Feather uses bundleIdentifier + top-level downloadURL as its UI/download ID.
        # AltStore/SideStore require unique actual bundle IDs instead.
        identity = (app["bundleIdentifier"], app.get("downloadURL")) if feather else app["bundleIdentifier"]
        require(identity not in ids, "Duplicate mod download" if feather else "Duplicate app bundle ID")
        ids.add(identity)
        if feather:
            require(app.get("downloadURL"), "Feather mod is missing its download identity")
        require(app["versions"], "App has no versions")
        seen = set()
        for version in app["versions"]:
            identity = (version["version"], version["buildVersion"])
            require(identity not in seen, "Duplicate version/build")
            seen.add(identity)
            require(version["size"] > 0 and version["downloadURL"].startswith("https://"), "Invalid download")
            datetime.fromisoformat(version["date"].replace("Z", "+00:00"))


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--releases-file", type=Path)
    parser.add_argument("--ipa-dir", type=Path)
    args = parser.parse_args()
    config = json.loads((ROOT / "source-config.json").read_text())
    repo = config["releasesRepository"]
    releases = json.loads(args.releases_file.read_text()) if args.releases_file else fetch_releases(repo)
    cache_path = ROOT / ".metadata.json"
    old_cache = json.loads(cache_path.read_text()) if cache_path.exists() else {}
    cached = old_cache.get("assets", {}) if old_cache.get("schemaVersion") == CACHE_VERSION else {}
    assets, records = {}, []
    for release, asset in select_assets(releases, config.get("includePrereleases", False)):
        key = str(asset["id"])
        fingerprint = {field: asset.get(field) for field in ("id", "size", "updated_at", "digest", "browser_download_url")}
        prior = cached.get(key, {})
        if prior.get("fingerprint") == fingerprint:
            metadata = prior["metadata"]
        else:
            print(f"Reading IPA {asset['id']}: {asset['name']}", flush=True)
            metadata = get_metadata(asset, repo, args.ipa_dir)
        assets[key] = {"fingerprint": fingerprint, "metadata": metadata}
        records.append({"assetId": asset["id"], "assetName": asset["name"], "releaseTag": release["tag_name"],
                        "date": release["published_at"], "downloadURL": asset["browser_download_url"], "size": asset["size"],
                        "description": f"{asset['name']}\nRelease: {release['tag_name']}\n\n{release.get('body') or ''}", "metadata": metadata})
    grouped = defaultdict(list)
    for record in records:
        grouped[record["metadata"]["bundleIdentifier"]].append(record)
    apps = [make_mod_app(record, config) for record in records]
    source = make_source(config, apps)
    source["description"] = "Every published IPA mod listed separately for Feather, including mods sharing the same bundle ID and version."
    validate_source(source, feather=True)
    classic_apps = [make_app(group, config) for _, group in sorted(grouped.items())]
    classic = make_source(config, classic_apps, "altstore", f"{config['name']} · AltStore / SideStore", "altstore.json")
    validate_source(classic)
    variants = {}
    for record in records:
        key = str(record["assetId"])
        variant = make_source(config, [make_mod_app(record, config)], key, f"{config['name']} · {record['assetName']}")
        validate_source(variant)
        variants[key] = variant
        record["sourceURL"] = variant["sourceURL"]
    # All downloads and validation finish before replacing any published data.
    write_json(ROOT / "source.json", source)
    write_json(ROOT / "altstore.json", classic)
    for key, variant in variants.items():
        write_json(ROOT / "sources" / f"{key}.json", variant)
    for stale in (ROOT / "sources").glob("*.json"):
        if stale.stem not in variants:
            stale.unlink()
    write_json(ROOT / "catalog.json", {"releasesRepository": repo, "assets": records})
    write_json(cache_path, {"schemaVersion": CACHE_VERSION, "assets": assets})
    rows = ["# IPA mods", "", "The main Feather source lists every IPA below separately. These individual source links also let AltStore Classic / SideStore users choose a specific mod with its real app identity.", "", "| IPA | Release | Version (build) | Source | Download |", "| --- | --- | --- | --- | --- |"]
    for r in records:
        name = r["assetName"].replace("|", "&#124;").replace("[", "&#91;").replace("]", "&#93;").replace("\n", " ")
        tag = r["releaseTag"].replace("|", "&#124;").replace("\n", " ")
        m = r["metadata"]
        rows.append(f"| {name} | {tag} | {m['version']} ({m['buildVersion']}) | [Source JSON]({r['sourceURL']}) | [IPA]({r['downloadURL']}) |")
    (ROOT / "CATALOG.md").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"Generated source.json: {len(apps)} apps, {len(records)} IPA assets, {len(variants)} individual sources")


if __name__ == "__main__":
    main()
