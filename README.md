# 23aces IPA Repo

A source for **Feather, SideStore, and AltStore Classic**, generated from public IPA assets in [the23aces/ipas releases](https://github.com/the23aces/ipas/releases).

## Add the source

Paste this URL into your app's Add Source / Add Repository screen:

```text
https://raw.githubusercontent.com/the23aces/repo/main/source.json
```

In Feather, open the Sources tab, tap **+**, and paste the URL. Refresh the source to see changes. Downloads point straight to GitHub release assets; GitHub Pages is not required.

## Choose an IPA variant

The main source groups apps by their actual bundle ID, with the newest published release first. If multiple files have the same bundle ID, version, and build, only the newest upload appears in the main source. Versions and bundle IDs are never invented to disguise duplicates.

The initial four IPAs all report `com.spotify.client`, version `9.1.86`, build `918602428`. The main source therefore selects the file from release `1.2`.

**[Browse every IPA and its individual source link](CATALOG.md)** to select an older upload or alternative variant. Add the individual Source JSON URL instead of the main source when you want that exact asset. Apps with the same bundle ID normally replace each other when installed.

## Automatic updates

GitHub Actions checks `the23aces/ipas` every hour at minute 17 and updates this repository only when its generated data changes. GitHub can delay scheduled jobs. You can also use **Actions → Update IPA source → Run workflow**. Published non-prerelease releases are included; drafts and prereleases are excluded by default.

The first run is triggered when this workflow is pushed. A release in another repository does not trigger this workflow immediately: it is discovered on the next scheduled check. GitHub may disable schedules in public repositories after 60 days without repository activity; re-enable the workflow in Actions if that happens.

No personal access token is needed: GitHub's built-in Actions token reads release metadata and commits generated files in this repository. Public downloads need no credentials. No secret is embedded in the feed.

## How metadata is generated

- Reads real bundle IDs, names, version/build numbers, and minimum iOS versions from each IPA's `Info.plist`.
- Reads entitlement names from Mach-O code signatures and privacy descriptions from the app and extension plists.
- Checks download size and GitHub's SHA-256 digest when provided.
- Caches metadata by asset ID, update time, size, URL, and digest, so unchanged IPAs are not downloaded again.
- Uses the publisher's GitHub avatar as the default icon. Override app name, icon, developer credit, or description under `apps` in `source-config.json`, keyed by the real bundle ID.
- Never runs or modifies an IPA. Invalid metadata makes the update fail, preserving the previously published feed.

If you replace an IPA without changing its embedded version/build, the download link updates but AltStore/SideStore may not report a new app update. Refresh and reinstall that variant, or publish a build with a new version/build number.

This is a download catalog. Signing and device installation remain the responsibility of your sideloading app and its existing setup. AltStore PAL uses a separate notarized distribution format; this feed targets AltStore Classic. Source metadata is validated, but installation has not been tested on a physical iPhone.

## Development

Python 3.11 or newer; no pip dependencies.

```sh
python3 -m unittest discover -s tests -v
python3 scripts/update_source.py
```

Generated files: `source.json`, `sources/*.json`, `catalog.json`, `CATALOG.md`, and `.metadata.json`. To change metadata, edit `source-config.json` or the generator rather than a generated file.

References: [AltStore source specification](https://faq.altstore.io/developers/make-a-source), [SideStore sources](https://docs.sidestore.io/docs/advanced/app-sources), [Feather](https://github.com/claration/feather).
