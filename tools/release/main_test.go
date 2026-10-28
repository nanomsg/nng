// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const testHeader = `// Keep this comment and the unrelated declaration.
#define NNG_MAJOR_VERSION 2
#define NNG_MINOR_VERSION 1
#define NNG_PATCH_VERSION 0
#define NNG_RELEASE_SUFFIX "dev"
int unrelated;
`

func gitTest(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func writeTest(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testRepo(t *testing.T) repository {
	t.Helper()
	dir := t.TempDir()
	gitTest(t, dir, "init", "--initial-branch=main")
	for key, value := range map[string]string{
		"user.name": "Release Test", "user.email": "release@example.invalid",
		"commit.gpgsign": "false", "tag.gpgsign": "false",
		"core.hooksPath": filepath.Join(dir, ".git", "hooks"),
	} {
		gitTest(t, dir, "config", key, value)
	}
	writeTest(t, filepath.Join(dir, headerPath), testHeader)
	gitTest(t, dir, "add", ".")
	gitTest(t, dir, "commit", "-m", "initial")
	return repository{dir: dir, out: io.Discard}
}

func prepareTest(t *testing.T, r repository) {
	t.Helper()
	if err := r.prepare(version{major: 2, minor: 1}, version{major: 2, minor: 2}); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareAndAtomicPush(t *testing.T) {
	r := testRepo(t)
	initial := gitTest(t, r.dir, "rev-parse", "HEAD")
	gitTest(t, r.dir, "tag", "-a", "do-not-publish", "-m", "Unrelated local tag")
	gitTest(t, r.dir, "config", "push.followTags", "true")
	prepareTest(t, r)
	if got := gitTest(t, r.dir, "rev-parse", "v2.1.0^{}"); got == initial {
		t.Fatal("tag points to the old development commit")
	}
	if got := gitTest(t, r.dir, "cat-file", "-t", "v2.1.0"); got != "tag" {
		t.Fatalf("expected annotated tag, got %s", got)
	}
	released := gitTest(t, r.dir, "show", "v2.1.0:"+headerPath)
	if released != strings.TrimSpace(replaceVersion(testHeader, version{major: 2, minor: 1})) {
		t.Fatalf("unexpected release header: %s", released)
	}
	development := gitTest(t, r.dir, "show", "HEAD:"+headerPath)
	if development != strings.TrimSpace(replaceVersion(testHeader, version{major: 2, minor: 2, suffix: "dev"})) {
		t.Fatalf("unexpected development header: %s", development)
	}
	if got := gitTest(t, r.dir, "rev-list", "--count", initial+"..HEAD"); got != "2" {
		t.Fatalf("expected two commits, got %s", got)
	}
	if err := r.checkPrepared("v2.1.0"); err != nil {
		t.Fatal(err)
	}
	remote := t.TempDir()
	gitTest(t, remote, "init", "--bare")
	gitTest(t, r.dir, "remote", "add", "origin", remote)
	if err := r.push("v2.1.0"); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"refs/heads/main", "refs/tags/v2.1.0"} {
		if gitTest(t, remote, "rev-parse", ref) != gitTest(t, r.dir, "rev-parse", ref) {
			t.Fatalf("remote %s does not match", ref)
		}
	}
	if tags := gitTest(t, remote, "tag", "--list"); tags != "v2.1.0" {
		t.Fatalf("pushed unrelated tags: %s", tags)
	}
}

func TestPreflightDoesNotModifyCheckout(t *testing.T) {
	cases := map[string]func(*testing.T, repository){
		"wrong branch":   func(t *testing.T, r repository) { gitTest(t, r.dir, "checkout", "-b", "feature") },
		"untracked file": func(t *testing.T, r repository) { writeTest(t, filepath.Join(r.dir, "unexpected"), "data") },
		"staged file": func(t *testing.T, r repository) {
			writeTest(t, filepath.Join(r.dir, "unexpected"), "data")
			gitTest(t, r.dir, "add", "unexpected")
		},
		"existing tag": func(t *testing.T, r repository) { gitTest(t, r.dir, "tag", "v2.1.0") },
		"wrong version": func(t *testing.T, r repository) {
			writeTest(t, filepath.Join(r.dir, headerPath), replaceVersion(testHeader, version{major: 2, minor: 2, suffix: "dev"}))
			gitTest(t, r.dir, "commit", "-am", "wrong version")
		},
		"already final": func(t *testing.T, r repository) {
			writeTest(t, filepath.Join(r.dir, headerPath), replaceVersion(testHeader, version{major: 2, minor: 1}))
			gitTest(t, r.dir, "commit", "-am", "already final")
		},
		"duplicate definition": func(t *testing.T, r repository) {
			writeTest(t, filepath.Join(r.dir, headerPath), testHeader+"#define NNG_MINOR_VERSION 1\n")
			gitTest(t, r.dir, "commit", "-am", "duplicate")
		},
		"merge in progress": func(t *testing.T, r repository) {
			writeTest(t, filepath.Join(r.dir, ".git", "MERGE_HEAD"), gitTest(t, r.dir, "rev-parse", "HEAD")+"\n")
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			r := testRepo(t)
			setup(t, r)
			before, _ := os.ReadFile(filepath.Join(r.dir, headerPath))
			head := gitTest(t, r.dir, "rev-parse", "HEAD")
			status := gitTest(t, r.dir, "status", "--porcelain")
			tags := gitTest(t, r.dir, "tag", "--list")
			if err := r.prepare(version{major: 2, minor: 1}, version{major: 2, minor: 2}); err == nil {
				t.Fatal("expected refusal")
			}
			after, _ := os.ReadFile(filepath.Join(r.dir, headerPath))
			if string(before) != string(after) || head != gitTest(t, r.dir, "rev-parse", "HEAD") ||
				status != gitTest(t, r.dir, "status", "--porcelain") || tags != gitTest(t, r.dir, "tag", "--list") {
				t.Fatal("preflight failure modified the checkout")
			}
		})
	}
}

func TestInvalidVersions(t *testing.T) {
	for _, s := range []string{"2.1", "v2.1.0", "02.1.0", "2.1.0-dev", "-1.0.0", "4294967296.0.0", "2.1.0\n"} {
		if _, err := parseVersion(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	r := testRepo(t)
	for _, next := range []version{{major: 2, minor: 1}, {major: 2}} {
		if err := r.prepare(version{major: 2, minor: 1}, next); err == nil {
			t.Errorf("accepted next version %s", next)
		}
	}
}

func TestRequiredArguments(t *testing.T) {
	for _, args := range [][]string{
		nil, {"prepare"}, {"prepare", "2.1.0"},
		{"prepare", "--dry-run"},
		{"prepare", "--minor", "--micro"},
		{"prepare", "--major", "--next", "3.0.0"},
		{"prepare", "2.1.0", "--next", "2.2.0", "extra"},
		{"prepare", "2.1.0", "--next", "2.2.0-dev"},
		{"check", "v2.1.0", "extra"}, {"push", "v2.1.0", "extra"},
		{"unknown", "2.1.0"},
	} {
		if err := run(args, io.Discard); err == nil {
			t.Errorf("accepted invalid arguments %v", args)
		}
	}
}

func TestInferredVersionPreparation(t *testing.T) {
	for _, tc := range []struct {
		flag string
		next string
	}{{"--minor", "2.2.0-dev"}, {"--micro", "2.1.8-dev"}, {"--major", "3.0.0-dev"}} {
		t.Run(tc.flag, func(t *testing.T) {
			r := testRepo(t)
			writeTest(t, filepath.Join(r.dir, headerPath), replaceVersion(testHeader, version{major: 2, minor: 1, patch: 7, suffix: "dev"}))
			gitTest(t, r.dir, "commit", "-am", "start at nonzero micro")
			opts, err := parsePrepare([]string{tc.flag, "--force"}, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.prepareRelease(opts); err != nil {
				t.Fatal(err)
			}
			if err := r.checkPrepared("v2.1.7"); err != nil {
				t.Fatal(err)
			}
			data := gitTest(t, r.dir, "show", "HEAD:"+headerPath)
			next, err := readVersion(data)
			if err != nil || next.String() != tc.next {
				t.Fatalf("next version = %s, %v; want %s", next, err, tc.next)
			}
		})
	}
}

func TestDryRunPreservesRepository(t *testing.T) {
	for _, dirty := range []bool{false, true} {
		t.Run(fmt.Sprint(dirty), func(t *testing.T) {
			r := testRepo(t)
			if dirty {
				gitTest(t, r.dir, "checkout", "-b", "feature")
				writeTest(t, filepath.Join(r.dir, headerPath), replaceVersion(testHeader, version{major: 2, minor: 1, patch: 7, suffix: "dev"}))
				writeTest(t, filepath.Join(r.dir, "untracked"), "keep me")
			}
			before, _ := os.ReadFile(filepath.Join(r.dir, headerPath))
			refs := gitTest(t, r.dir, "show-ref")
			status := gitTest(t, r.dir, "status", "--porcelain")
			var output bytes.Buffer
			r.out = &output
			opts, err := parsePrepare([]string{"--minor", "--dry-run"}, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.prepareRelease(opts); err != nil {
				t.Fatal(err)
			}
			release := "2.1.0"
			if dirty {
				release = "2.1.7"
			}
			for _, want := range []string{"Current: " + release + "-dev", "Release: " + release + " (tag v" + release + ")", "Next development: 2.2.0-dev", "Dry run:"} {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("preview missing %q: %s", want, &output)
				}
			}
			if !strings.Contains(output.String(), "WARNING: --docs was not supplied") {
				t.Fatal("missing documentation reminder")
			}
			after, _ := os.ReadFile(filepath.Join(r.dir, headerPath))
			if string(before) != string(after) || refs != gitTest(t, r.dir, "show-ref") || status != gitTest(t, r.dir, "status", "--porcelain") {
				t.Fatal("dry run modified the repository")
			}
		})
	}
}

func TestInferredVersionLimitsAndExplicitOverrides(t *testing.T) {
	for _, tc := range []struct {
		current version
		args    []string
	}{
		{version{major: 4294967295, suffix: "dev"}, []string{"--major"}},
		{version{major: 2, minor: 4294967295, suffix: "dev"}, []string{"--minor"}},
		{version{major: 2, minor: 1, patch: 4294967295, suffix: "dev"}, []string{"--micro"}},
		{version{major: 2, minor: 1}, []string{"--minor"}},
		{version{major: 2, minor: 1, suffix: "dev"}, []string{"2.2.0", "--minor"}},
		{version{major: 2, minor: 1, suffix: "dev"}, []string{"--next", "2.1.0"}},
	} {
		opts, err := parsePrepare(tc.args, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := opts.versions(replaceVersion(testHeader, tc.current)); err == nil {
			t.Errorf("accepted %s with %v", tc.current, tc.args)
		}
	}
	for _, args := range [][]string{
		{"2.1.0", "--next", "2.2.0"},
		{"--next", "2.2.0"},
		{"--minor", "2.1.0"},
	} {
		opts, err := parsePrepare(args, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		_, release, next, err := opts.versions(testHeader)
		if err != nil || release.String() != "2.1.0" || next.String() != "2.2.0" {
			t.Fatalf("%v: release %s next %s, %v", args, release, next, err)
		}
	}
}

func TestCheckRejectsMismatchedTags(t *testing.T) {
	r := testRepo(t)
	gitTest(t, r.dir, "tag", "v2.1.0")
	if err := r.check("v2.1.0"); err == nil {
		t.Fatal("accepted a development suffix on a final tag")
	}
	prepareRepo := testRepo(t)
	prepareTest(t, prepareRepo)
	gitTest(t, prepareRepo.dir, "tag", "v2.2.0", "v2.1.0^{}")
	for _, tag := range []string{"v2.2.0", "2.1.0", "v2.1.0-rc.1", "v9.0.0"} {
		if err := prepareRepo.check(tag); err == nil {
			t.Errorf("accepted %s", tag)
		}
	}
}

func TestPushPreflightRejectsUnrelatedChanges(t *testing.T) {
	r := testRepo(t)
	prepareTest(t, r)
	writeTest(t, filepath.Join(r.dir, "unrelated"), "data")
	gitTest(t, r.dir, "add", "unrelated")
	gitTest(t, r.dir, "commit", "--amend", "--no-edit")
	if err := r.checkPrepared("v2.1.0"); err == nil {
		t.Fatal("accepted unrelated changes in the development bump")
	}
}

func TestFailedDevelopmentCommitDoesNotCreateTag(t *testing.T) {
	r := testRepo(t)
	hook := filepath.Join(r.dir, ".git", "hooks", "pre-commit")
	writeTest(t, hook, "#!/bin/sh\nif git show :include/nng/nng.h | grep -q 'NNG_RELEASE_SUFFIX \"dev\"'; then exit 1; fi\n")
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}
	err := r.prepare(version{major: 2, minor: 1}, version{major: 2, minor: 2})
	if err == nil || !strings.Contains(err.Error(), "development bump failed") {
		t.Fatalf("expected actionable failure, got %v", err)
	}
	if got := gitTest(t, r.dir, "tag", "--list"); got != "" {
		t.Fatalf("created tag despite failed development bump: %s", got)
	}
	if err := r.checkPrepared("v2.1.0"); err == nil {
		t.Fatal("incomplete preparation passed push preflight")
	}
}

func TestAtomicPushRejectsBothRefs(t *testing.T) {
	r := testRepo(t)
	remote := t.TempDir()
	gitTest(t, remote, "init", "--bare")
	gitTest(t, r.dir, "remote", "add", "origin", remote)
	gitTest(t, r.dir, "push", "origin", "main")
	initial := gitTest(t, remote, "rev-parse", "main")
	prepareTest(t, r)
	hook := filepath.Join(remote, "hooks", "update")
	writeTest(t, hook, "#!/bin/sh\n[ \"$1\" != refs/tags/v2.1.0 ]\n")
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := r.push("v2.1.0"); err == nil {
		t.Fatal("expected remote rejection")
	}
	if initial != gitTest(t, remote, "rev-parse", "main") || gitTest(t, remote, "tag", "--list") != "" {
		t.Fatal("atomic push left a partially updated remote")
	}
}
