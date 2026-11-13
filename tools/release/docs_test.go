// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const initialManifest = `{
  "latest_version": "/ref/v2.0/",
  "versions": [
    {"id":"v2.0","label":"NNG 2.0","href":"/ref/v2.0/"},
    {"id":"dev","label":"Development (unreleased)","href":"/ref/dev/"}
  ]
}
`

func readTest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func seedManifest(t *testing.T, r repository) {
	t.Helper()
	writeTest(t, filepath.Join(r.dir, manifestPath), initialManifest)
	gitTest(t, r.dir, "add", manifestPath)
	gitTest(t, r.dir, "commit", "-m", "manual manifest")
}

func TestDocsPreparationIsSelectable(t *testing.T) {
	for _, docs := range []bool{false, true} {
		name := "without docs"
		if docs {
			name = "with docs"
		}
		t.Run(name, func(t *testing.T) {
			r := testRepo(t)
			seedManifest(t, r)
			var output bytes.Buffer
			r.out = &output
			if err := r.prepareRelease(prepareOptions{bump: "minor", docs: docs, force: true}); err != nil {
				t.Fatal(err)
			}
			if err := r.checkPrepared("v2.1.0"); err != nil {
				t.Fatal(err)
			}
			manifest, err := readManifest(filepath.Join(r.dir, manifestPath))
			if err != nil {
				t.Fatal(err)
			}
			want := "/ref/v2.0/"
			if docs {
				want = "/ref/v2.1/"
			}
			if manifest.Latest != want {
				t.Fatalf("latest = %s; want %s", manifest.Latest, want)
			}
			released := gitTest(t, r.dir, "show", "v2.1.0:"+manifestPath)
			if !strings.Contains(released, want) {
				t.Fatal("tag does not carry the docs choice")
			}
			if strings.Contains(output.String(), "WARNING:") == docs {
				t.Fatal("documentation reminder does not match the docs flag")
			}
		})
	}
}

func TestDocsDryRunDoesNotWriteManifest(t *testing.T) {
	r := testRepo(t)
	seedManifest(t, r)
	gitTest(t, r.dir, "checkout", "-b", "preview")
	before := gitTest(t, r.dir, "show-ref")
	if err := r.prepareRelease(prepareOptions{bump: "minor", docs: true, dryRun: true}); err != nil {
		t.Fatal(err)
	}
	if got := readTest(t, filepath.Join(r.dir, manifestPath)); got != initialManifest {
		t.Fatal("preview changed manifest")
	}
	if gitTest(t, r.dir, "show-ref") != before || gitTest(t, r.dir, "status", "--porcelain") != "" {
		t.Fatal("preview changed Git state")
	}
}

func TestPrepareConfirmation(t *testing.T) {
	for _, input := range []string{"", "no\n", "yes\n", "v2.2.0\n", "v2.1.0", "v2.1.0\r", "v2.1.0 "} {
		r := testRepo(t)
		r.in = strings.NewReader(input)
		head := gitTest(t, r.dir, "rev-parse", "HEAD")
		if err := r.prepareRelease(prepareOptions{bump: "minor"}); err == nil || !strings.Contains(err.Error(), "canceled") {
			t.Fatalf("expected cancellation for %q, got %v", input, err)
		}
		if head != gitTest(t, r.dir, "rev-parse", "HEAD") || gitTest(t, r.dir, "status", "--porcelain") != "" || gitTest(t, r.dir, "tag", "--list") != "" {
			t.Fatal("cancellation modified repository")
		}
	}
	r := testRepo(t)
	r.in = strings.NewReader("v2.1.0\n")
	if err := r.prepareRelease(prepareOptions{bump: "minor"}); err != nil {
		t.Fatal(err)
	}
	if err := r.checkPrepared("v2.1.0"); err != nil {
		t.Fatal(err)
	}
}

func TestForceKeepsSafetyChecks(t *testing.T) {
	r := testRepo(t)
	r.in = strings.NewReader("")
	gitTest(t, r.dir, "checkout", "-b", "feature")
	if err := r.prepareRelease(prepareOptions{bump: "minor", force: true}); err == nil || !strings.Contains(err.Error(), "run from main") {
		t.Fatalf("force bypassed main check: %v", err)
	}
	gitTest(t, r.dir, "checkout", "main")
	if err := r.prepareRelease(prepareOptions{bump: "minor", force: true}); err != nil {
		t.Fatalf("force did not bypass confirmation: %v", err)
	}
}

func TestPushConfirmation(t *testing.T) {
	for _, mode := range []string{"cancel", "unterminated tag", "confirm", "force"} {
		t.Run(mode, func(t *testing.T) {
			r := testRepo(t)
			prepareTest(t, r)
			remote := t.TempDir()
			gitTest(t, remote, "init", "--bare")
			gitTest(t, r.dir, "remote", "add", "origin", remote)
			args := []string{"v2.1.0"}
			r.in = strings.NewReader("")
			if mode == "confirm" {
				r.in = strings.NewReader("v2.1.0\n")
			}
			if mode == "unterminated tag" {
				r.in = strings.NewReader("v2.1.0")
			}
			if mode == "force" {
				args = append(args, "--force")
			}
			err := r.pushRelease(args)
			if mode == "cancel" || mode == "unterminated tag" {
				if err == nil || !strings.Contains(err.Error(), "canceled") || gitTest(t, remote, "for-each-ref", "--format=%(refname)") != "" {
					t.Fatal("canceled push changed remote")
				}
			} else if err != nil {
				t.Fatal(err)
			} else if gitTest(t, remote, "rev-parse", "main") != gitTest(t, r.dir, "rev-parse", "HEAD") {
				t.Fatal("confirmed push did not update remote")
			}
		})
	}
}

type failedConfirmationReader struct {
	err error
}

func (r failedConfirmationReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestConfirmationReadError(t *testing.T) {
	want := errors.New("input failed")
	r := repository{in: failedConfirmationReader{err: want}, out: io.Discard}
	if err := r.confirm("v2.1.0", "prepare"); !errors.Is(err, want) {
		t.Fatalf("confirmation did not preserve the read error: %v", err)
	}
	// A complete CRLF-terminated line remains valid terminal input.
	r.in = strings.NewReader("v2.1.0\r\n")
	if err := r.confirm("v2.1.0", "prepare"); err != nil {
		t.Fatal(err)
	}
}

type docsFixture struct {
	pages, book, source, redirect string
}

func newDocsFixture(t *testing.T) docsFixture {
	t.Helper()
	r := testRepo(t)
	dir := t.TempDir()
	f := docsFixture{pages: r.dir, book: filepath.Join(dir, "book"), source: filepath.Join(dir, "versions.json"), redirect: filepath.Join(dir, "redirect.html")}
	writeTest(t, filepath.Join(f.pages, "ref/v2.0/index.html"), "stable 2.0")
	writeTest(t, filepath.Join(f.pages, "ref/dev/index.html"), "old dev")
	writeTest(t, filepath.Join(f.pages, "ref/dev/versions.json"), initialManifest)
	writeTest(t, filepath.Join(f.pages, "ref/obsolete.html"), "obsolete unversioned page")
	writeTest(t, filepath.Join(f.pages, "CNAME"), "example.invalid")
	writeTest(t, filepath.Join(f.book, "index.html"), "new manual")
	writeTest(t, filepath.Join(f.book, "assets/style.css"), "new styles")
	writeTest(t, f.source, initialManifest)
	writeTest(t, f.redirect, "redirect to __LATEST_VERSION__")
	gitTest(t, f.pages, "add", ".")
	gitTest(t, f.pages, "commit", "-m", "published docs")
	return f
}

func (f docsFixture) request(t *testing.T, line string) {
	t.Helper()
	manifest, err := readManifest(f.source)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Latest = "/ref/" + line + "/"
	manifest.Versions = append(manifest.Versions, docEntry{ID: line, Label: "NNG " + strings.TrimPrefix(line, "v"), Href: "/ref/" + line + "/"})
	data, err := encodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTest(t, f.source, string(data))
}

func (f docsFixture) publish(line string) error {
	return publishDocs(f.pages, f.book, line, f.source, f.redirect)
}

func (f docsFixture) latest(t *testing.T, want string, selected bool) {
	t.Helper()
	manifest, err := readManifest(filepath.Join(f.pages, "ref/dev/versions.json"))
	if err != nil || manifest.Latest != want {
		t.Fatalf("latest = %s, %v; want %s", manifest.Latest, err, want)
	}
	found := false
	for _, entry := range manifest.Versions {
		found = found || entry.ID == "v2.1"
	}
	if found != selected {
		t.Fatalf("2.1 selector presence = %t; want %t", found, selected)
	}
	if redirect := readTest(t, filepath.Join(f.pages, "ref/index.html")); !strings.Contains(redirect, want) {
		t.Fatalf("incorrect redirect: %s", redirect)
	}
}

func TestDocsPromoteOnlyDeployedManualAndPreserveLatest(t *testing.T) {
	f := newDocsFixture(t)
	f.request(t, "v2.1")
	if err := f.publish("dev"); err != nil {
		t.Fatal(err)
	}
	f.latest(t, "/ref/v2.0/", false)
	if err := f.publish("v2.1"); err != nil {
		t.Fatal(err)
	}
	f.latest(t, "/ref/v2.1/", true)
	if readTest(t, filepath.Join(f.pages, "ref/v2.1/index.html")) != "new manual" || readTest(t, filepath.Join(f.pages, "ref/v2.0/index.html")) != "stable 2.0" || readTest(t, filepath.Join(f.pages, "CNAME")) != "example.invalid" {
		t.Fatal("manual or unrelated site files changed incorrectly")
	}
	if _, err := os.Stat(filepath.Join(f.pages, "ref/obsolete.html")); !os.IsNotExist(err) {
		t.Fatal("obsolete unversioned assets remain")
	}
	// A later dev build or historical republication may use an older source.
	writeTest(t, f.source, initialManifest)
	for _, line := range []string{"dev", "v2.0", "v1.12"} {
		if err := f.publish(line); err != nil {
			t.Fatal(err)
		}
		f.latest(t, "/ref/v2.1/", true)
	}
	// Repeating publication should not create another pages commit.
	gitTest(t, f.pages, "add", ".")
	gitTest(t, f.pages, "commit", "-m", "updated docs")
	if err := f.publish("v1.12"); err != nil {
		t.Fatal(err)
	}
	if gitTest(t, f.pages, "status", "--porcelain") != "" {
		t.Fatal("repeated publication is not idempotent")
	}
}

func TestDocsWithoutPromotionAndFutureRequest(t *testing.T) {
	f := newDocsFixture(t)
	if err := f.publish("v2.1"); err != nil {
		t.Fatal(err)
	}
	f.latest(t, "/ref/v2.0/", false)
	f.request(t, "v2.2")
	if err := f.publish("dev"); err != nil {
		t.Fatal(err)
	}
	f.latest(t, "/ref/v2.0/", false)
}

func TestModernPublicationUpdatesLegacySelector(t *testing.T) {
	f := newDocsFixture(t)
	legacyDir := filepath.Join(f.pages, "ref/v1.12")
	writeTest(t, filepath.Join(legacyDir, "index.html"), "historical manual content")
	f.request(t, "v1.12")
	f.request(t, "v2.1")
	if err := f.publish("v2.1"); err != nil {
		t.Fatal(err)
	}
	manifest, err := readManifest(filepath.Join(legacyDir, "versions.json"))
	if err != nil || manifest.Latest != "/ref/v2.1/" {
		t.Fatalf("legacy selector was not updated: %s, %v", manifest.Latest, err)
	}
	if readTest(t, filepath.Join(legacyDir, "index.html")) != "historical manual content" {
		t.Fatal("modern publication changed historical manual content")
	}
	f.latest(t, "/ref/v2.1/", true)
}

func TestDevBuildDoesNotPromoteExistingManual(t *testing.T) {
	f := newDocsFixture(t)
	writeTest(t, filepath.Join(f.pages, "ref/v2.1/index.html"), "older 2.1 patch")
	f.request(t, "v2.1")
	if err := f.publish("dev"); err != nil {
		t.Fatal(err)
	}
	f.latest(t, "/ref/v2.0/", true)
	if err := f.publish("v2.1"); err != nil {
		t.Fatal(err)
	}
	f.latest(t, "/ref/v2.1/", true)
}

func TestDocsInvalidBuildDoesNotChangePublishedTree(t *testing.T) {
	for _, failure := range []string{"missing index", "symlink asset", "invalid manifest", "invalid redirect", "invalid line"} {
		t.Run(failure, func(t *testing.T) {
			f := newDocsFixture(t)
			line := "v2.1"
			switch failure {
			case "missing index":
				if err := os.Remove(filepath.Join(f.book, "index.html")); err != nil {
					t.Fatal(err)
				}
			case "symlink asset":
				if err := os.Symlink(f.source, filepath.Join(f.book, "linked")); err != nil {
					t.Fatal(err)
				}
			case "invalid manifest":
				writeTest(t, f.source, "{}")
			case "invalid redirect":
				writeTest(t, f.redirect, "missing placeholder")
			case "invalid line":
				line = "../../outside"
			}
			if err := f.publish(line); err == nil {
				t.Fatal("expected failure")
			}
			if gitTest(t, f.pages, "status", "--porcelain") != "" {
				t.Fatal("invalid publication changed pages checkout")
			}
		})
	}
}

func TestDocsPublishArguments(t *testing.T) {
	if err := runPublishDocs([]string{"--version", "dev"}, io.Discard); err == nil {
		t.Fatal("accepted incomplete publication arguments")
	}
}
