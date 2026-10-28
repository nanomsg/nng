# Releasing NNG

The release helper requires Git and Go 1.22 or newer, with no third-party Go
dependencies. Run it from the repository root. A standalone binary can also be
built with `go build -o /path/to/nng-release tools/release/main.go`.

## Prepare locally

Finish the release notes and reference documentation, merge their PRs, and
update your local `main` from `origin`. Check that its CI is green.

First preview the release and the next development version:

```sh
go run tools/release/main.go prepare --minor --docs --dry-run
```

With a header declaring `2.1.0-dev`, this prints:

```text
Current: 2.1.0-dev
Release: 2.1.0 (tag v2.1.0)
Next development: 2.2.0-dev
Docs: include /ref/v2.1/ and promote after deployment (without downgrading latest).
Dry run: preview only. Preparation requires a clean main checkout and an unused release tag.
```

The preview works on any branch, including a dirty checkout, and leaves files,
commits, and tags unchanged. It reads the working header and validates the
version choices; the checkout and tag preconditions are checked when actually
preparing the release.

To prepare the displayed transition:

```sh
go run tools/release/main.go prepare --minor --docs
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
go run tools/release/main.go prepare --next 2.2.0 --docs --dry-run
go run tools/release/main.go prepare 2.1.0 --next 2.2.0 --docs
```

Actual preparation requires a clean `main` checkout declaring a development
version, an unused local release tag, and a newer next version. The helper
changes all four version definitions in `include/nng/nng.h` together; CMake
derives its versions from that header.

`--docs` also adds the release line to `docs/versions.json` and requests it as
the latest stable manual, without downgrading a newer line. This manifest
change is included in the release commit and tag. Published selectors and
redirects advance only when that version's built manual is published.
Omitting `--docs` keeps the source manifest unchanged and prints a warning
reminder to review documentation routing before publication. Existing manual
publication still runs; the flag opts into selector and stable promotion.

Preparation prompts you to type the release tag, such as `v2.1.0`, before
creating commits. A mismatched answer or end of input cancels the operation.
Use `--force` to skip confirmation in automation; version, branch, and clean
checkout checks still apply. A dry run never prompts or makes changes.

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
Pushing also prompts for the exact release tag. `push v2.1.0 --force` skips
that confirmation and retains the atomic push and safety checks; it does not
force-update remote refs.

Wait for the **release / validate-tag** workflow to pass. It checks that the
tag's version matches the header with an empty suffix, then builds and tests
the exact tagged source in Release mode with Mbed TLS enabled. Other platform
checks on `main` validate the subsequent development commit.

### Recovering from a rejected push

A rejected atomic push leaves the remote refs unchanged, but the two prepared
commits and release tag still exist locally. Do not rerun `prepare` immediately:
the local header now declares the next development version, and the release
tag already exists. For a transient connection or permission problem, resolve
the problem and retry `push` with the existing prepared history.

Before rebuilding the release, check the remote tag:

```sh
git ls-remote --tags origin refs/tags/v2.1.0
```

If this command fails, resolve the connection or authentication problem first;
failure does not establish that the tag is absent. If it prints a tag, keep
the local history intact and inspect the remote tag and `origin/main` before
deciding how to proceed. The release may already have been pushed, or the
version may be in use by another commit. Do not overwrite a published tag;
`prepare` checks only local tags.

If the query succeeds with no output and the push was rejected because
`origin/main` advanced, inspect the local state:

```sh
git branch --show-current
git status --short
git log -2 --name-status
git rev-parse HEAD~2
git rev-parse HEAD^ 'v2.1.0^{commit}'
```

Continue only on a clean `main` with exactly the two expected preparation
commits and no additional work. The last command must print the same commit
twice: the release tag must point to the parent of the development bump.
Record the pre-release commit printed by `HEAD~2`, then preserve the prepared
history on a backup branch before removing the unpublished local tag:

```sh
git branch backup/release-v2.1.0 HEAD &&
git tag -d v2.1.0 &&
git reset --keep backup/release-v2.1.0~2 &&
git pull --ff-only origin main
```

The command chain stops on a failure, including an existing backup branch;
inspect and resolve that failure before continuing. The backup retains both
prepared commits. Preview the updated release plan, then run `prepare` again
using the intended increment and documentation choices:

```sh
go run tools/release/main.go prepare --minor --docs --dry-run
go run tools/release/main.go prepare --minor --docs
```

Review the regenerated commits and tag, then retry `push`. For branch-protection
rejections that require a PR, follow the PR procedure above rather than resetting
and repeatedly preparing the same release.

## Publish

Create the GitHub release from the existing `v2.1.0` tag after validation.
The helper leaves publication as a separate step.

The documentation workflow publishes the tagged manual to `/ref/v2.1/`.
For a release prepared with `--docs`, it publishes the manual, shared version
selector, and stable `/ref/` redirect together in one `gh-pages` commit, after
the manual builds successfully. Verify the selector and redirect after the
Pages deployment completes.

The source manifest records the requested latest version; the deployed
manifest at `/ref/dev/versions.json` records what is actually published.
Development builds hide version entries whose manuals are not deployed and
keep the stable redirect unchanged while release publication is pending.
Later development builds and historical manual republication retain the
latest deployed version, even if their source manifest is older.

Both mdBook and legacy AsciiDoc publication use the helper's `publish-docs`
command to stage this combined change in a local `gh-pages` checkout. The
workflow commits and pushes only after staging succeeds. Publication does
not edit `main`, and repeated publication is idempotent.

## Helper tests

```sh
go test tools/release/*.go
```

The tests use temporary repositories and local bare remotes, including
rejection of an atomic push. They do not prepare or publish a real release.
