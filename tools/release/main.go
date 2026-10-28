// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).

// release prepares NNG final releases using Git and the Go standard library.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const headerPath = "include/nng/nng.h"

const manifestPath = "docs/versions.json"

type version struct {
	major, minor, patch uint64
	suffix              string
}

func (v version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
	if v.suffix != "" {
		s += "-" + v.suffix
	}
	return s
}

func (v version) after(other version) bool {
	if v.major != other.major {
		return v.major > other.major
	}
	if v.minor != other.minor {
		return v.minor > other.minor
	}
	return v.patch > other.patch
}

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func parseVersion(s string) (version, error) {
	m := versionPattern.FindStringSubmatch(s)
	if m == nil {
		return version{}, fmt.Errorf("expected a final version such as 2.1.0; got %q", s)
	}
	var v version
	for i, p := range []*uint64{&v.major, &v.minor, &v.patch} {
		n, err := strconv.ParseUint(m[i+1], 10, 32)
		if err != nil {
			return version{}, fmt.Errorf("invalid version %q: %w", s, err)
		}
		*p = n
	}
	return v, nil
}

var fields = []string{"NNG_MAJOR_VERSION", "NNG_MINOR_VERSION", "NNG_PATCH_VERSION", "NNG_RELEASE_SUFFIX"}

func fieldPattern(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^#define[ \t]+` + name + `[ \t]+([^\r\n]+)`)
}

func readVersion(data string) (version, error) {
	values := make([]string, len(fields))
	for i, name := range fields {
		matches := fieldPattern(name).FindAllStringSubmatch(data, -1)
		if len(matches) != 1 {
			return version{}, fmt.Errorf("expected exactly one %s definition", name)
		}
		values[i] = strings.TrimSpace(matches[0][1])
	}
	v, err := parseVersion(strings.Join(values[:3], "."))
	if err != nil {
		return v, err
	}
	suffix, err := strconv.Unquote(values[3])
	if err != nil || (suffix != "" && suffix != "dev") {
		return v, fmt.Errorf("expected NNG_RELEASE_SUFFIX to be empty or dev; got %s", values[3])
	}
	v.suffix = suffix
	return v, nil
}

func replaceVersion(data string, v version) string {
	values := []string{fmt.Sprint(v.major), fmt.Sprint(v.minor), fmt.Sprint(v.patch), strconv.Quote(v.suffix)}
	for i, name := range fields {
		data = fieldPattern(name).ReplaceAllString(data, "#define "+name+" "+values[i])
	}
	return data
}

type prepareOptions struct {
	release, next, bump string
	dryRun              bool
	docs                bool
	force               bool
}

const prepareUsage = "usage: release prepare [VERSION] (--minor | --micro | --major | --next VERSION) [--docs] [--dry-run] [--force]"

func parsePrepare(args []string, out io.Writer) (prepareOptions, error) {
	var opts prepareOptions
	// Retain the original VERSION --next VERSION argument order.
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		opts.release, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("prepare", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&opts.next, "next", "", "explicit next development version")
	fs.BoolVar(&opts.dryRun, "dry-run", false, "preview versions without changing files, commits, or tags")
	fs.BoolVar(&opts.docs, "docs", false, "include the manual in the selector and request stable promotion after deployment")
	fs.BoolVar(&opts.force, "force", false, "skip confirmation (all safety checks still apply)")
	minor := fs.Bool("minor", false, "advance the next development minor version, resetting micro to zero")
	micro := fs.Bool("micro", false, "advance the next development micro (patch) version")
	major := fs.Bool("major", false, "advance the next development major version, resetting minor and micro to zero")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() == 1 && opts.release == "" {
		opts.release = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return opts, fmt.Errorf("%s", prepareUsage)
	}
	choices := 0
	if opts.next != "" {
		choices++
	}
	for _, choice := range []struct {
		name string
		set  bool
	}{{"minor", *minor}, {"micro", *micro}, {"major", *major}} {
		if choice.set {
			opts.bump = choice.name
			choices++
		}
	}
	if choices != 1 {
		return opts, fmt.Errorf("choose exactly one of --minor, --micro, --major, or --next VERSION")
	}
	return opts, nil
}

func (opts prepareOptions) versions(data string) (current, release, next version, err error) {
	current, err = readVersion(data)
	if err != nil {
		return
	}
	if current.suffix != "dev" {
		err = fmt.Errorf("expected a development version before release preparation; header declares %s", current)
		return
	}
	release = current
	release.suffix = ""
	if opts.release != "" {
		var requested version
		requested, err = parseVersion(opts.release)
		if err != nil {
			return
		}
		if requested != release {
			err = fmt.Errorf("requested release %s does not match the header version %s", requested, current)
			return
		}
	}
	if opts.next != "" {
		next, err = parseVersion(opts.next)
	} else {
		next = release
		switch opts.bump {
		case "major":
			next.major++
			next.minor, next.patch = 0, 0
		case "minor":
			next.minor++
			next.patch = 0
		case "micro":
			next.patch++
		default:
			err = fmt.Errorf("choose a next-version increment")
			return
		}
		// Apply the same integer limits to inferred and explicit versions.
		next, err = parseVersion(next.String())
	}
	if err == nil && !next.after(release) {
		err = fmt.Errorf("next development version %s must be newer than %s", next, release)
	}
	return
}

type repository struct {
	dir string
	out io.Writer
	in  io.Reader
}

func (r repository) confirm(tag, action string) error {
	fmt.Fprintf(r.out, "Type %s to %s: ", tag, action)
	input := r.in
	if input == nil {
		input = os.Stdin
	}
	line, err := bufio.NewReader(input).ReadString('\n')
	if err == io.EOF {
		return fmt.Errorf("canceled: input ended before confirmation for %s", tag)
	}
	if err != nil {
		return fmt.Errorf("read confirmation: %w", err)
	}
	if strings.TrimSpace(line) != tag {
		return fmt.Errorf("canceled: confirmation did not match %s", tag)
	}
	return nil
}

func (r repository) prepareRelease(opts prepareOptions) error {
	data, err := os.ReadFile(filepath.Join(r.dir, headerPath))
	if err != nil {
		return err
	}
	current, release, next, err := opts.versions(string(data))
	if err != nil {
		return err
	}
	development := next
	development.suffix = "dev"
	fmt.Fprintf(r.out, "Current: %s\nRelease: %s (tag v%s)\nNext development: %s\n", current, release, release, development)
	if opts.docs {
		if _, err := r.releaseManifest(release); err != nil {
			return err
		}
		fmt.Fprintf(r.out, "Docs: include /ref/%s/ and promote after deployment (without downgrading latest).\n", docLine(release))
	} else {
		fmt.Fprintln(r.out, "WARNING: --docs was not supplied; review the documentation selector and latest redirect before publishing.")
	}
	if opts.dryRun {
		fmt.Fprintln(r.out, "Dry run: preview only. Preparation requires a clean main checkout and an unused release tag.")
		return nil
	}
	if err := r.cleanMain(); err != nil {
		return err
	}
	if !opts.force {
		if err := r.confirm("v"+release.String(), "prepare the release and next development commits"); err != nil {
			return err
		}
	}
	return r.prepareWithDocs(release, next, opts.docs)
}

func (r repository) git(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w\n%s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output)), nil
}

func (r repository) cleanMain() error {
	branch, err := r.git("symbolic-ref", "--short", "HEAD")
	if err != nil {
		return err
	}
	if branch != "main" {
		return fmt.Errorf("run from main; current branch is %s", branch)
	}
	status, err := r.git("status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return err
	}
	if status != "" {
		return fmt.Errorf("commit or remove working tree changes before preparing or pushing a release:\n%s", status)
	}
	for _, state := range []string{"MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply"} {
		path, err := r.git("rev-parse", "--git-path", state)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(r.dir, path)
		}
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("finish the Git operation recorded by %s first", state)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func tagVersion(tag string) (version, error) {
	if !strings.HasPrefix(tag, "v") {
		return version{}, fmt.Errorf("expected a tag such as v2.1.0; got %q", tag)
	}
	return parseVersion(strings.TrimPrefix(tag, "v"))
}

func (r repository) check(tag string) error {
	want, err := tagVersion(tag)
	if err != nil {
		return err
	}
	data, err := r.git("show", "refs/tags/"+tag+":"+headerPath)
	if err != nil {
		return err
	}
	got, err := readVersion(data)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("tag %s requires version %s with an empty suffix; header declares %s", tag, want, got)
	}
	fmt.Fprintf(r.out, "%s matches the tagged header (%s).\n", tag, got)
	return nil
}

func (r repository) commitVersion(data string, v version, message string, extraPaths ...string) error {
	if err := os.WriteFile(filepath.Join(r.dir, headerPath), []byte(replaceVersion(data, v)), 0o644); err != nil {
		return err
	}
	if _, err := r.git(append([]string{"add", "--", headerPath}, extraPaths...)...); err != nil {
		return err
	}
	_, err := r.git("commit", "-m", message)
	return err
}

func (r repository) prepare(release, next version) error {
	return r.prepareWithDocs(release, next, false)
}

func (r repository) prepareWithDocs(release, next version, docs bool) error {
	if !next.after(release) {
		return fmt.Errorf("next development version %s must be newer than %s", next, release)
	}
	if err := r.cleanMain(); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(r.dir, headerPath))
	if err != nil {
		return err
	}
	got, err := readVersion(string(data))
	if err != nil {
		return err
	}
	want := release
	want.suffix = "dev"
	if got != want {
		return fmt.Errorf("expected %s before release preparation; header declares %s", want, got)
	}
	tag := "v" + release.String()
	existing, err := r.git("tag", "--list", tag)
	if err != nil {
		return err
	}
	if existing != "" {
		return fmt.Errorf("tag %s already exists", tag)
	}
	var manifest []byte
	if docs {
		manifest, err = r.releaseManifest(release)
		if err != nil {
			return err
		}
	}
	// Check identity before editing. Git commit/tag retain normal signing and hooks.
	if _, err := r.git("var", "GIT_AUTHOR_IDENT"); err != nil {
		return err
	}
	if _, err := r.git("var", "GIT_COMMITTER_IDENT"); err != nil {
		return err
	}
	var extraPaths []string
	if docs {
		if err := os.WriteFile(filepath.Join(r.dir, manifestPath), manifest, 0o644); err != nil {
			return err
		}
		extraPaths = append(extraPaths, manifestPath)
	}
	if err := r.commitVersion(string(data), release, "release: prepare "+tag, extraPaths...); err != nil {
		return fmt.Errorf("release commit failed; inspect git status before retrying: %w", err)
	}
	releaseCommit, err := r.git("rev-parse", "HEAD")
	if err != nil {
		return err
	}
	next.suffix = "dev"
	if err := r.commitVersion(string(data), next, "release: start "+next.String()); err != nil {
		return fmt.Errorf("release commit %s exists, but the development bump failed; finish that commit before creating %s: %w", releaseCommit, tag, err)
	}
	// Create the tag last, after main has returned to a development version.
	if _, err := r.git("tag", "-a", tag, releaseCommit, "-m", "NNG "+release.String()); err != nil {
		return fmt.Errorf("both version commits exist; tag creation failed (release commit %s): %w", releaseCommit, err)
	}
	if err := r.checkPrepared(tag); err != nil {
		return err
	}
	fmt.Fprintf(r.out, "Prepared %s at %s; main is now %s.\nReview git log -2 -p, then run:\n  go run tools/release/main.go push %s\n", tag, releaseCommit, next, tag)
	return nil
}

func (r repository) checkPrepared(tag string) error {
	if err := r.cleanMain(); err != nil {
		return err
	}
	if err := r.check(tag); err != nil {
		return err
	}
	releaseCommit, err := r.git("rev-parse", "refs/tags/"+tag+"^{commit}")
	if err != nil {
		return err
	}
	parents, err := r.git("rev-list", "--parents", "-n", "1", "HEAD")
	if err != nil {
		return err
	}
	p := strings.Fields(parents)
	if len(p) != 2 || p[1] != releaseCommit {
		return fmt.Errorf("main must be exactly one development-version commit after %s", tag)
	}
	releaseData, err := r.git("show", releaseCommit+":"+headerPath)
	if err != nil {
		return err
	}
	data, err := r.git("show", "HEAD:"+headerPath)
	if err != nil {
		return err
	}
	next, err := readVersion(data)
	if err != nil {
		return err
	}
	release, _ := tagVersion(tag)
	if next.suffix != "dev" || !next.after(release) {
		return fmt.Errorf("main must declare a newer development version; got %s", next)
	}
	changed, err := r.git("diff", "--name-only", releaseCommit, "HEAD")
	if err != nil {
		return err
	}
	if changed != headerPath || replaceVersion(releaseData, next) != data {
		return fmt.Errorf("the commit after %s must change only the four version definitions", tag)
	}
	return nil
}

func (r repository) push(tag string) error {
	if err := r.checkPrepared(tag); err != nil {
		return err
	}
	output, err := r.git("push", "--atomic", "--no-follow-tags", "origin", "refs/heads/main", "refs/tags/"+tag)
	if err != nil {
		return err
	}
	fmt.Fprintln(r.out, output)
	fmt.Fprintf(r.out, "Pushed main and %s. Wait for release / validate-tag before publishing.\n", tag)
	return nil
}

func (r repository) pushRelease(args []string) error {
	tag := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		tag, args = args[0], args[1:]
	}
	flags := flag.NewFlagSet("push", flag.ContinueOnError)
	flags.SetOutput(r.out)
	force := flags.Bool("force", false, "skip confirmation (all safety checks still apply)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() == 1 && tag == "" {
		tag = flags.Arg(0)
	} else if flags.NArg() != 0 {
		return fmt.Errorf("usage: release push TAG [--force]")
	}
	if tag == "" {
		return fmt.Errorf("usage: release push TAG [--force]")
	}
	if err := r.checkPrepared(tag); err != nil {
		return err
	}
	if !*force {
		if err := r.confirm(tag, "push main and the release tag to origin"); err != nil {
			return err
		}
	}
	return r.push(tag)
}

type docEntry struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Href  string `json:"href"`
}

type docManifest struct {
	Latest   string     `json:"latest_version"`
	Versions []docEntry `json:"versions"`
}

func docLine(v version) string {
	return fmt.Sprintf("v%d.%d", v.major, v.minor)
}

func parseDocLine(line string) (version, error) {
	if !strings.HasPrefix(line, "v") {
		return version{}, fmt.Errorf("invalid manual version %q", line)
	}
	return parseVersion(strings.TrimPrefix(line, "v") + ".0")
}

func readManifest(path string) (docManifest, error) {
	var manifest docManifest
	data, err := os.ReadFile(path)
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("read %s: %w", path, err)
	}
	seen := map[string]bool{}
	for _, entry := range manifest.Versions {
		if entry.ID != "dev" {
			if _, err := parseDocLine(entry.ID); err != nil {
				return manifest, err
			}
		}
		if seen[entry.ID] || entry.Href != "/ref/"+entry.ID+"/" || entry.Label == "" {
			return manifest, fmt.Errorf("invalid or duplicate manual entry %q in %s", entry.ID, path)
		}
		seen[entry.ID] = true
	}
	line := strings.TrimSuffix(strings.TrimPrefix(manifest.Latest, "/ref/"), "/")
	if _, err := parseDocLine(line); err != nil || manifest.Latest != "/ref/"+line+"/" || !seen[line] {
		return manifest, fmt.Errorf("invalid latest_version %q in %s", manifest.Latest, path)
	}
	return manifest, nil
}

func encodeManifest(manifest docManifest) ([]byte, error) {
	sort.Slice(manifest.Versions, func(i, j int) bool {
		a, b := manifest.Versions[i].ID, manifest.Versions[j].ID
		if a == "dev" || b == "dev" {
			return b == "dev" && a != "dev"
		}
		va, _ := parseDocLine(a)
		vb, _ := parseDocLine(b)
		return vb.after(va)
	})
	data, err := json.MarshalIndent(manifest, "", "  ")
	return append(data, '\n'), err
}

func (r repository) releaseManifest(release version) ([]byte, error) {
	manifest, err := readManifest(filepath.Join(r.dir, manifestPath))
	if err != nil {
		return nil, err
	}
	line := docLine(release)
	found := false
	for _, entry := range manifest.Versions {
		found = found || entry.ID == line
	}
	if !found {
		manifest.Versions = append(manifest.Versions, docEntry{ID: line, Label: "NNG " + strings.TrimPrefix(line, "v"), Href: "/ref/" + line + "/"})
	}
	latest, _ := parseDocLine(strings.TrimSuffix(strings.TrimPrefix(manifest.Latest, "/ref/"), "/"))
	if requested, _ := parseDocLine(line); requested.after(latest) {
		manifest.Latest = "/ref/" + line + "/"
	}
	return encodeManifest(manifest)
}

func deployedManual(pages, line string) bool {
	dir := filepath.Join(pages, "ref", line)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	info, err = os.Lstat(filepath.Join(dir, "index.html"))
	return err == nil && info.Mode().IsRegular()
}

func writePublishedFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".nng-docs-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(0o644); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// Publication combines the built manual, shared selector, and stable redirect
// in one gh-pages commit. A requested future manual stays hidden until built.
func publishDocs(pages, book, line, sourceManifest, redirectTemplate string) error {
	if line != "dev" {
		if _, err := parseDocLine(line); err != nil {
			return err
		}
	}
	manifest, err := readManifest(sourceManifest)
	if err != nil {
		return err
	}
	redirect, err := os.ReadFile(redirectTemplate)
	if err != nil {
		return err
	}
	if !strings.Contains(string(redirect), "__LATEST_VERSION__") {
		return fmt.Errorf("redirect template has no __LATEST_VERSION__ placeholder")
	}
	// Never follow output-directory symlinks when replacing a deployed manual.
	for _, path := range []string{pages, filepath.Join(pages, "ref"), filepath.Join(pages, "ref", "dev"), filepath.Join(pages, "ref", line)} {
		info, err := os.Lstat(path)
		if err == nil && !info.IsDir() {
			return fmt.Errorf("publication directory is not a regular directory: %s", path)
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	var previous docManifest
	previous, err = readManifest(filepath.Join(pages, "ref", "dev", "versions.json"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// Read every input asset before replacing anything in the local pages tree.
	assets := map[string][]byte{}
	err = filepath.WalkDir(book, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("manual asset is a symlink: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("manual asset is not a regular file: %s", path)
		}
		relative, err := filepath.Rel(book, path)
		if err != nil {
			return err
		}
		assets[relative], err = os.ReadFile(path)
		return err
	})
	if err != nil {
		return err
	}
	if _, ok := assets["index.html"]; !ok {
		return fmt.Errorf("built manual has no index.html: %s", book)
	}
	// Compute the resulting selector before changing output files.
	available := func(id string) bool { return id == line || deployedManual(pages, id) }
	if previous.Latest != "" {
		id := strings.TrimSuffix(strings.TrimPrefix(previous.Latest, "/ref/"), "/")
		if !available(id) {
			return fmt.Errorf("the currently published stable manual is missing: %s", previous.Latest)
		}
	}
	entries := map[string]docEntry{}
	for _, m := range []docManifest{previous, manifest} {
		for _, entry := range m.Versions {
			if available(entry.ID) {
				entries[entry.ID] = entry
			}
		}
	}
	var latest version
	latestPath := ""
	for i, candidate := range []string{previous.Latest, manifest.Latest} {
		id := strings.TrimSuffix(strings.TrimPrefix(candidate, "/ref/"), "/")
		// A dev build cannot promote a pending release request, even when an
		// older patch's manual already occupies the requested release line.
		if i == 1 && previous.Latest != "" && id != line {
			continue
		}
		v, err := parseDocLine(id)
		if err == nil && available(id) && entries[id].ID != "" && (latestPath == "" || v.after(latest)) {
			latest, latestPath = v, candidate
		}
	}
	if latestPath == "" {
		return fmt.Errorf("no deployed stable manual matches the current or requested latest_version")
	}
	result := docManifest{Latest: latestPath}
	for _, entry := range entries {
		result.Versions = append(result.Versions, entry)
	}
	encoded, err := encodeManifest(result)
	if err != nil {
		return err
	}
	destination := filepath.Join(pages, "ref", line)
	if err := os.RemoveAll(destination); err != nil {
		return err
	}
	for name, data := range assets {
		path := filepath.Join(destination, name)
		if err := writePublishedFile(path, data); err != nil {
			return err
		}
	}
	// /ref/dev/versions.json is shared by existing version-selector scripts.
	directories := map[string]bool{"dev": true, line: true}
	for _, entry := range result.Versions {
		directories[entry.ID] = true
	}
	for id := range directories {
		dir := filepath.Join(pages, "ref", id)
		if err := writePublishedFile(filepath.Join(dir, "versions.json"), encoded); err != nil {
			return err
		}
	}
	// Retain versioned manuals while replacing obsolete unversioned assets.
	children, err := os.ReadDir(filepath.Join(pages, "ref"))
	if err != nil {
		return err
	}
	for _, child := range children {
		_, versionErr := parseDocLine(child.Name())
		if child.Name() != "dev" && child.Name() != "index.html" && versionErr != nil {
			if err := os.RemoveAll(filepath.Join(pages, "ref", child.Name())); err != nil {
				return err
			}
		}
	}
	return writePublishedFile(filepath.Join(pages, "ref", "index.html"), []byte(strings.ReplaceAll(string(redirect), "__LATEST_VERSION__", latestPath)))
}

func runPublishDocs(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("publish-docs", flag.ContinueOnError)
	flags.SetOutput(out)
	pages := flags.String("pages", "", "local gh-pages checkout to update")
	book := flags.String("book", "", "built manual directory")
	line := flags.String("version", "", "manual line, such as v2.1 or dev")
	manifest := flags.String("manifest", "", "source version manifest")
	redirect := flags.String("redirect-template", "", "stable redirect template")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *pages == "" || *book == "" || *line == "" || *manifest == "" || *redirect == "" || flags.NArg() != 0 {
		return fmt.Errorf("publish-docs requires --pages, --book, --version, --manifest, and --redirect-template")
	}
	return publishDocs(*pages, *book, *line, *manifest, *redirect)
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("%s | release check TAG | release push TAG", prepareUsage)
	}
	if args[0] == "publish-docs" {
		return runPublishDocs(args[1:], out)
	}
	r := repository{out: out}
	root, err := r.git("rev-parse", "--show-toplevel")
	if err != nil {
		return err
	}
	r.dir = root
	switch args[0] {
	case "prepare":
		opts, err := parsePrepare(args[1:], out)
		if err != nil {
			return err
		}
		return r.prepareRelease(opts)
	case "check", "push":
		if args[0] == "push" {
			return r.pushRelease(args[1:])
		}
		if len(args) != 2 {
			return fmt.Errorf("%s requires exactly one tag", args[0])
		}
		return r.check(args[1])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}
