// Copyright 2026 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).

// release prepares NNG final releases using Git and the Go standard library.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const headerPath = "include/nng/nng.h"

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
}

const prepareUsage = "usage: release prepare [VERSION] (--minor | --micro | --major | --next VERSION) [--dry-run]"

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
	if opts.dryRun {
		fmt.Fprintln(r.out, "Dry run: preview only. Preparation requires a clean main checkout and an unused release tag.")
		return nil
	}
	return r.prepare(release, next)
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

func (r repository) commitVersion(data string, v version, message string) error {
	if err := os.WriteFile(filepath.Join(r.dir, headerPath), []byte(replaceVersion(data, v)), 0o644); err != nil {
		return err
	}
	if _, err := r.git("add", "--", headerPath); err != nil {
		return err
	}
	_, err := r.git("commit", "-m", message)
	return err
}

func (r repository) prepare(release, next version) error {
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
	// Check identity before editing. Git commit/tag retain normal signing and hooks.
	if _, err := r.git("var", "GIT_AUTHOR_IDENT"); err != nil {
		return err
	}
	if _, err := r.git("var", "GIT_COMMITTER_IDENT"); err != nil {
		return err
	}
	if err := r.commitVersion(string(data), release, "release: prepare "+tag); err != nil {
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

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("%s | release check TAG | release push TAG", prepareUsage)
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
		if len(args) != 2 {
			return fmt.Errorf("%s requires exactly one tag", args[0])
		}
		if args[0] == "check" {
			return r.check(args[1])
		}
		return r.push(args[1])
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
