# 23aces IPA Repo

Sources generated from public IPA assets in [the23aces/ipas releases](https://github.com/the23aces/ipas/releases). The main **Feather** source lists each mod separately. Separate feeds support **SideStore and AltStore Classic**.

## Add the Feather source

Paste this URL into Feather's Add Source / Add Repository screen:

```text
https://raw.githubusercontent.com/the23aces/repo/main/source.json
```

In Feather, open the Sources tab, tap **+**, and paste the URL. Refresh the source to see changes. Downloads point straight to GitHub release assets; GitHub Pages is not required.

## Every mod is a separate listing

Every published IPA asset appears separately in `source.json`, newest releases first. Names identify the mods using their filenames, with optional readable names in `source-config.json` → `assetNames`. Future IPA uploads automatically become separate listings too.

The initial four mods all report `com.spotify.client`, version `9.1.86`, build `918602428`. Feather distinguishes their listings by the bundle ID and download URL, so all four can be listed with their real metadata. The IPA files are not modified. Apps sharing a bundle ID normally replace each other when installed; separate source listings do not automatically make them install side by side.

**[Browse all mods and their individual source links](CATALOG.md)**.

## AltStore Classic and SideStore

These clients require unique actual bundle IDs in a source. Use an individual Source JSON URL from the catalog above to choose a particular mod, or this grouped feed for the newest upload of each app:

```text
https://raw.githubusercontent.com/the23aces/repo/main/altstore.json
```

The grouped feed combines versions by bundle ID and chooses the newest asset when the version and build also match. Use `source.json` in Feather to see **every mod at once**.

## Automatic updates

GitHub Actions checks `the23aces/ipas` every hour at minute 17 and updates this repository only when its generated data changes. GitHub can delay scheduled jobs. You can also use **Actions → Update IPA source → Run workflow**. Published non-prerelease releases are included; drafts and prereleases are excluded by default.

The first run is triggered when this workflow is pushed. A release in another repository does not trigger this workflow immediately: it is discovered on the next scheduled check. GitHub may disable schedules in public repositories after 60 days without repository activity; re-enable the workflow in Actions if that happens.

No personal access token is needed: GitHub's built-in Actions token reads release metadata and commits generated files in this repository. Public downloads need no credentials. No secret is embedded in the feed.

## How metadata is generated

- Reads real bundle IDs, names, version/build numbers, and minimum iOS versions from each IPA's `Info.plist`.
- Reads entitlement names from Mach-O code signatures and privacy descriptions from the app and extension plists.
- Checks download size and GitHub's SHA-256 digest when provided.
- Caches metadata by asset ID, update time, size, URL, and digest, so unchanged IPAs are not downloaded again.
- Uses the publisher's GitHub avatar as the default icon. Override icon, developer credit, or grouped-app metadata under `apps` in `source-config.json`, keyed by the real bundle ID. Set each mod's display name under `assetNames`, keyed by its GitHub release asset ID.
- Never runs or modifies an IPA. Invalid metadata makes the update fail, preserving the previously published feed.

If you replace an IPA without changing its embedded version/build, the download link updates but AltStore/SideStore may not report a new app update. Refresh and reinstall that variant, or publish a build with a new version/build number.

This is a download catalog. Signing and device installation remain the responsibility of your sideloading app and its existing setup. AltStore PAL uses a separate notarized distribution format; this feed targets AltStore Classic. Source metadata is validated, but installation has not been tested on a physical iPhone.

## Development

Python 3.11 or newer; no pip dependencies.

```sh
python3 -m unittest discover -s tests -v
python3 scripts/update_source.py
```

Generated files: `source.json` (all Feather mods), `altstore.json` (grouped AltStore/SideStore feed), `sources/*.json`, `catalog.json`, `CATALOG.md`, and `.metadata.json`. To change metadata, edit `source-config.json` or the generator rather than a generated file.

References: [AltStore source specification](https://faq.altstore.io/developers/make-a-source), [SideStore sources](https://docs.sidestore.io/docs/advanced/app-sources), [Feather](https://github.com/claration/feather).
