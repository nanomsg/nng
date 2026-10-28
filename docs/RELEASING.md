# Releasing NNG

The release helper requires Git and Go 1.22 or newer, with no third-party Go
dependencies. Run it from the repository root. A standalone binary can also be
built with `go build -o /path/to/nng-release tools/release/main.go`.

## Prepare locally

Finish the release notes and reference documentation, merge their PRs, and
update your local `main` from `origin`. Check that its CI is green.

First preview the release and the next development version:

```sh
go run tools/release/main.go prepare --minor --dry-run
```

With a header declaring `2.1.0-dev`, this prints:

```text
Current: 2.1.0-dev
Release: 2.1.0 (tag v2.1.0)
Next development: 2.2.0-dev
Dry run: preview only. Preparation requires a clean main checkout and an unused release tag.
```

The preview works on any branch, including a dirty checkout, and leaves files,
commits, and tags unchanged. It reads the working header and validates the
version choices; the checkout and tag preconditions are checked when actually
preparing the release.

To prepare the displayed transition:

```sh
go run tools/release/main.go prepare --minor
```

The release version is detected from `include/nng/nng.h` by removing its `dev`
suffix. Choose exactly one flag to select the **next development version**:

| Flag | Example starting at `2.1.7-dev` | Lower components |
| --- | --- | --- |
| `--minor` | Release `2.1.7`, then `2.2.0-dev` | Resets micro to zero. |
| `--micro` | Release `2.1.7`, then `2.1.8-dev` | Preserves major and minor. |
| `--major` | Release `2.1.7`, then `3.0.0-dev` | Resets minor and micro to zero. |

Micro is the patch field (`NNG_PATCH_VERSION`). An explicit next version is
also supported, with an optional release version to check against the header:

```sh
go run tools/release/main.go prepare --next 2.2.0 --dry-run
go run tools/release/main.go prepare 2.1.0 --next 2.2.0
```

Actual preparation requires a clean `main` checkout declaring a development
version, an unused local release tag, and a newer next version. The helper
changes all four version definitions in `include/nng/nng.h` together; CMake
derives its versions from that header.

It creates two commits: the final `2.1.0` version with an empty suffix, then
`2.2.0-dev`. After both commits succeed, it creates an annotated `v2.1.0` tag
on the first commit. Normal Git commit hooks and signing configuration apply.
The commands create local Git history; run preparation without other Git
writers operating on the checkout.

Review the result:

```sh
git log -2 -p
git show v2.1.0
go run tools/release/main.go check v2.1.0
```

If a hook, signing operation, or Git command fails, preparation stops and
reports the failure. Inspect `git status` and `git log` before continuing.
For example, if the development commit fails, the release commit exists and
the next development header is staged, but the tag has not been created.
Fix the reported problem, commit the development bump, and create the tag
on the release commit reported by the helper. The helper does not reset or
discard changes automatically. Its push command rejects incomplete preparation.

## Push and validate

```sh
go run tools/release/main.go push v2.1.0
```

This rechecks the tag/header match and requires `main` to be exactly one
version-only development commit after the release. It atomically pushes
`main` and the tag to `origin`, so a rejected branch or tag update leaves both
remote refs unchanged. Existing remote tags and branch protection remain in
effect. The remote must allow the intended branch update; if it requires PRs,
preserve both commits through the PR and publish the existing tag afterward.
Squashing the two commits would remove the release commit from main's history.

Wait for the **release / validate-tag** workflow to pass. It checks that the
tag's version matches the header with an empty suffix, then builds and tests
the exact tagged source in Release mode with Mbed TLS enabled. Other platform
checks on `main` validate the subsequent development commit.

## Publish

Create the GitHub release from the existing `v2.1.0` tag after validation.
The helper leaves publication as a separate step.

The documentation workflow publishes the tagged manual to `/ref/v2.1/`.
Coordinate the 2.1 entry and `latest_version` in `docs/versions.json` with
publication, then verify the version selector and stable `/ref/` redirect.
Advance the stable redirect once the new manual exists. The helper manages
library versions and Git refs; documentation content and routing are reviewed
separately.

## Helper tests

```sh
go test tools/release/main.go tools/release/main_test.go
```

The tests use temporary repositories and local bare remotes, including
rejection of an atomic push. They do not prepare or publish a real release.
