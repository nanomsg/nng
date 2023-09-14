// Copyright 2020 Staysail Systems, Inc.
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/bytesparadise/libasciidoc"
	"github.com/bytesparadise/libasciidoc/pkg/configuration"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/uuid"
	jww "github.com/spf13/jwalterweatherman"
)

type Configuration struct {
	Version string
	Debug   bool
	Trace   bool
	Quiet   bool
	DryRun  bool
	Author  string
	Email   string
	Url     string
	Message string
}

var Config Configuration

func init() {
	flag.StringVar(&Config.Version, "v", "tip", "Version to publish")
	flag.BoolVar(&Config.Debug, "d", false, "Enable debugging")
	flag.BoolVar(&Config.Trace, "t", false, "Enable tracing")
	flag.BoolVar(&Config.Quiet, "q", false, "Run quietly")
	flag.BoolVar(&Config.DryRun, "n", false, "Dry run, does not push changes")
	flag.StringVar(&Config.Url, "u", "ssh://git@github.com/nanomsg/nng.git", "URL of repo to publish from")
	flag.StringVar(&Config.Email, "E", "info@staysail.tech", "Author email for commit")
	flag.StringVar(&Config.Author, "A", "Staysail Systems, Inc.", "Author name for commit")
	flag.StringVar(&Config.Message, "m", "", "Commit message")
}

func (g *Global) CheckError(err error, prefix string, args ...interface{}) {
	if err == nil {
		g.Log.TRACE.Printf("%s: ok", fmt.Sprintf(prefix, args...))
		return
	}
	g.Log.FATAL.Fatalf("Error: %s: %v", fmt.Sprintf(prefix, args...), err)
}

func (g *Global) Fatal(format string, args ...interface{}) {
	g.Log.FATAL.Fatalf("Error: %s", fmt.Sprintf(format, args...))
}

type Section struct {
	Name        string
	Synopsis    string
	Description string
	Pages       []*Page
}

type Page struct {
	Name        string
	Section     string
	Description string
	Content     string
}

type Global struct {
	Config   Configuration
	SrcFs    billy.Filesystem
	DstFs    billy.Filesystem
	DstDir   string
	LaConfig *configuration.Configuration
	Sections map[string]*Section
	Pages    map[string]*Page
	Repo     *git.Repository
	Index    string
	ToC      string
	Added    map[string]bool
	WorkTree *git.Worktree
	Branch   string
	OldHash  plumbing.Hash
	NewHash  plumbing.Hash
	Log      *jww.Notepad
}

func (g *Global) Init() {
	g.Config = Config
	g.Sections = make(map[string]*Section)
	g.Pages = make(map[string]*Page)
	g.Added = make(map[string]bool)
	g.SrcFs = memfs.New()
	g.DstFs = memfs.New()
	g.DstDir = path.Join("man", g.Config.Version)
	g.LaConfig = configuration.NewConfiguration(
		configuration.WithAttributes(map[string]interface{}{
			"nofooter":           "yes",
			"icons":              "font",
			"linkcss":            "yes",
			"source-highlighter": "pygments",
		}))
	thresh := jww.LevelInfo
	if g.Config.Quiet {
		thresh = jww.LevelError
	}
	if g.Config.Debug {
		thresh = jww.LevelDebug
	}
	if g.Config.Trace {
		thresh = jww.LevelTrace
	}
	g.Log = jww.NewNotepad(thresh, thresh, os.Stdout, ioutil.Discard, "", log.Ldate|log.Ltime)
}

func (g *Global) Destroy() {
}

func (g *Global) Debug(format string, args ...interface{}) {
	g.Log.DEBUG.Printf(format, args...)
}

func (g *Global) Print(format string, args ...interface{}) {
	g.Log.INFO.Printf(format, args...)
}

func (g *Global) CloneSource() {
	tag := g.Config.Version
	if tag == "" || tag == "tip" {
		tag = "master"
	}
	ref := plumbing.NewBranchReferenceName(tag)
	if strings.HasPrefix(tag, "v") {
		ref = plumbing.NewTagReferenceName(tag)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	now := time.Now()
	_, err := git.CloneContext(ctx, memory.NewStorage(), g.SrcFs, &git.CloneOptions{
		URL:           g.Config.Url,
		ReferenceName: ref,
	})
	g.CheckError(err, "clone source")
	g.Debug("Cloned source (%s) in %v", tag, time.Since(now))
}

func (g *Global) ClonePages() {
	ref := plumbing.NewBranchReferenceName("gh-pages")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	now := time.Now()
	repo, err := git.CloneContext(ctx, memory.NewStorage(), g.DstFs, &git.CloneOptions{
		URL:           g.Config.Url,
		ReferenceName: ref,
		RemoteName:    "origin",
	})
	g.CheckError(err, "clone gh-pages")
	g.Repo = repo
	g.Debug("Cloned pages in %v", time.Since(now))
}

func (g *Global) ProcessManPage(page os.FileInfo) {
	source := g.ReadFile(page.Name())
	// Let's look for the description
	inName := false
	desc := ""
	name := ""
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimRight(line, " \t\r")
		if line == "" {
			continue
		}
		if line == "== NAME" {
			inName = true
			continue
		}
		if inName {
			w := strings.SplitN(line, " - ", 2)
			if len(w) != 2 || w[1] == "" {
				g.Fatal("page %s NAME malformed", page.Name())
			}
			name = w[0]
			desc = w[1]
			strings.TrimSpace(name)
			strings.TrimSpace(desc)
			break
		}
	}

	if desc == "" {
		g.Fatal("page %s NAME missing", page.Name())
	}

	html := &strings.Builder{}

	// Emit the title, as we are not letting libasciidoc do it (stripping headers)
	cfg := g.LaConfig
	cfg.Filename = page.Name()
	cfg.LastUpdated = page.ModTime()
	metadata, err := libasciidoc.Convert(strings.NewReader(source), html, cfg)
	g.CheckError(err, "processing page %s", page.Name())
	w := strings.SplitN(metadata.Title, "(", 2)
	sect := strings.TrimSuffix(w[1], ")")
	if len(w) != 2 || name != w[0] || !strings.HasSuffix(w[1], ")") {
		g.Fatal("page %s title incorrect (%s)", page.Name(), name)
	}
	if page.Name() != name+"."+sect+".adoc" {
		g.Fatal("page %s(%s) does not match file name %s", name, sect, page.Name())
	}
	result := &strings.Builder{}
	_, _ = fmt.Fprintf(result, "---\n")
	_, _ = fmt.Fprintf(result, "version: %s\n", g.Config.Version)
	_, _ = fmt.Fprintf(result, "layout: %s\n", "manpage_v2")
	_, _ = fmt.Fprintf(result, "title: %s\n", fmt.Sprintf("%s(%s)", name, sect))
	_, _ = fmt.Fprintf(result, "---\n")
	_, _ = fmt.Fprintf(result, "<h1>%s(%s)</h1>\n", name, sect)
	result.WriteString(html.String())

	g.Pages[page.Name()] = &Page{
		Name:        name,
		Section:     sect,
		Description: desc,
		Content:     result.String(),
	}
	g.Log.TRACE.Printf("HTML for %s:\n%s\n", name, result.String())
}

func (g *Global) ReadFile(name string) string {
	f, err := g.SrcFs.Open(path.Join("docs/man", name))
	g.CheckError(err, "open file %s", name)
	b, err := ioutil.ReadAll(f)
	g.CheckError(err, "read file %s", name)
	return string(b)
}

func (g *Global) LoadSection(name string) {
	section := strings.TrimPrefix(name, "man")

	g.Sections[section] = &Section{
		Name:        section,
		Synopsis:    g.ReadFile(name + ".sect"),
		Description: g.ReadFile(name + ".desc"),
	}
}

func (g *Global) ProcessSource() {
	pages, err := g.SrcFs.ReadDir("docs/man")
	g.CheckError(err, "reading source directory")
	count := 0
	g.Debug("Total of %d files in man directory", len(pages))
	now := time.Now()
	for _, page := range pages {
		if page.IsDir() {
			continue
		}
		if strings.HasSuffix(page.Name(), ".sect") {
			g.LoadSection(strings.TrimSuffix(page.Name(), ".sect"))
		}
		if !strings.HasSuffix(page.Name(), ".adoc") {
			continue
		}
		g.ProcessManPage(page)
		count++
	}
	g.Debug("Processed %d pages in %v", count, time.Since(now))
}

func (g *Global) GenerateToC() {
	toc := &strings.Builder{}
	idx := &strings.Builder{}

	for _, page := range g.Pages {
		if sect := g.Sections[page.Section]; sect == nil {
			g.Fatal("page %s section %s not found", page.Name, page.Section)
		} else {
			sect.Pages = append(sect.Pages, page)
		}
	}

	var sects []string
	for name, sect := range g.Sections {
		sects = append(sects, name)
		sort.Slice(sect.Pages, func(i, j int) bool { return sect.Pages[i].Name < sect.Pages[j].Name })
	}
	sort.Strings(sects)

	// And also the index page.

	// Emit the toc leader part
	toc.WriteString("<nav id=\"toc\" class=\"toc2\">\n")
	toc.WriteString("<div id=\"toctitle\">Table of Contents</div>\n")
	toc.WriteString("<ul class=\"sectlevel1\n\">\n")

	idx.WriteString("= NNG Reference Manual\n")

	for _, sect := range sects {
		s := g.Sections[sect]
		_, _ = fmt.Fprintf(toc, "<li>%s</li>\n", s.Synopsis)
		_, _ = fmt.Fprintf(toc, "<ul class=\"sectlevel2\">\n")

		_, _ = fmt.Fprintf(idx, "\n== Section %s: %s\n\n", s.Name, s.Synopsis)
		_, _ = fmt.Fprintln(idx, s.Description)
		_, _ = fmt.Fprintln(idx, "\n[cols=\"3,5\"]\n|===")

		for _, page := range s.Pages {
			_, _ = fmt.Fprintf(toc, "<li><a href=\"%s.%s.html\">%s</a></li>\n",
				page.Name, page.Section, page.Name)
			_, _ = fmt.Fprintf(idx, "|xref:%s.%s.adoc[%s(%s)]\n", page.Name, page.Section,
				page.Name, page.Section)
			_, _ = fmt.Fprintf(idx, "|%s\n", page.Description)
		}

		_, _ = fmt.Fprintf(toc, "</ul>\n")
		_, _ = fmt.Fprintln(idx, "|===")
	}
	_, _ = fmt.Fprintf(toc, "</ul>\n")
	_, _ = fmt.Fprintf(toc, "</nav>\n")

	index := &strings.Builder{}
	_, _ = fmt.Fprintf(index, "---\n")
	_, _ = fmt.Fprintf(index, "version: %s\n", g.Config.Version)
	_, _ = fmt.Fprintf(index, "layout: %s\n", "manpage_v2")
	_, _ = fmt.Fprintf(index, "---\n")
	_, _ = fmt.Fprintf(index, "<h1>NNG Reference Manual</h1>\n")

	cfg := g.LaConfig
	cfg.Filename = "index.adoc"
	_, err := libasciidoc.Convert(strings.NewReader(idx.String()), index, cfg)
	g.CheckError(err, "formatting index")
	g.Index = index.String()
	g.ToC = toc.String()
}

func (g *Global) CreateBranch() {
	brName := uuid.New().String()
	var err error

	refName := plumbing.ReferenceName("refs/heads/" + brName)
	g.Branch = brName

	g.WorkTree, err = g.Repo.Worktree()
	g.CheckError(err, "getting worktree")

	err = g.WorkTree.Checkout(&git.CheckoutOptions{
		Branch: refName,
		Create: true,
	})
	g.CheckError(err, "creating branch")
	g.Print("Checked out branch %v", brName)
	pr, err := g.Repo.Head()
	g.CheckError(err, "getting head hash")
	g.OldHash = pr.Hash()
}

func (g *Global) WriteFile(name string, content string) {
	full := path.Join(g.DstDir, name)
	f, err := g.DstFs.Create(full)
	g.CheckError(err, "creating file %s", name)
	_, err = f.Write([]byte(content))
	g.CheckError(err, "writing file %s", name)
	err = f.Close()
	g.CheckError(err, "closing file %s", name)
	g.Add(name)
}

func (g *Global) Add(name string) {
	g.Log.TRACE.Printf("Adding file %s", name)
	g.Added[name] = true
}

func (g *Global) Delete(name string) {
	g.Debug("Removing file %s", name)
	_, err := g.WorkTree.Remove(path.Join(g.DstDir, name))
	g.CheckError(err, "removing file %s", name)
}

func (g *Global) Commit() {
	if status, err := g.WorkTree.Status(); status == nil {
		g.CheckError(err, "obtaining status")
	} else if status.IsClean() {
		g.Print("No changes to commit.")
		return
	}
	message := g.Config.Message
	if message == "" {
		message = "Manual page updates for " + g.Config.Version
	}
	var err error
	g.NewHash, err = g.WorkTree.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Email: g.Config.Email,
			Name:  g.Config.Author,
			When:  time.Now(),
		},
	})
	g.CheckError(err, "committing branch")
}

func (g *Global) Push() {
	if g.NewHash.IsZero() {
		g.Print("Nothing to push.")
		return
	}

	ci, err := g.Repo.Log(&git.LogOptions{
		From: g.NewHash,
	})
	g.CheckError(err, "getting commit log")
	commit, err := ci.Next()
	g.CheckError(err, "getting single commit")
	if commit != nil {
		g.Print(commit.String())
		if fs, _ := commit.Stats(); fs != nil {
			g.Debug(fs.String())
		}
	}
	if g.Config.DryRun {
		g.Print("Not pushing changes (dry-run mode.)")
	} else {
		err := g.Repo.Push(&git.PushOptions{
			RemoteName: "origin",
		})
		g.CheckError(err, "pushing changes")
		g.Print("Pushed branch %v\n", g.Branch)
	}
}

func (g *Global) WriteOutput() {

	for _, p := range g.Pages {
		fName := fmt.Sprintf("%s.%s.html", p.Name, p.Section)
		g.WriteFile(fName, p.Content)
	}
	g.WriteFile("_toc.html", g.ToC)
	g.WriteFile("index.html", g.Index)

	_, err := g.WorkTree.Add(g.DstDir)
	g.CheckError(err, "adding directory")
	files, err := g.DstFs.ReadDir(g.DstDir)
	g.CheckError(err, "scanning destination directory")
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if g.Added[file.Name()] {
			continue
		}
		g.Delete(file.Name())
	}
	status, err := g.WorkTree.Status()
	g.CheckError(err, "obtaining commit status")
	if !status.IsClean() {
		g.Debug("No changes.")
	} else {
		g.Debug(status.String())
	}
}

func main() {
	g := &Global{}
	flag.Parse()
	g.Init()
	defer g.Destroy()

	g.CloneSource()
	g.ClonePages()
	g.ProcessSource()
	g.GenerateToC()
	g.CreateBranch()
	g.WriteOutput()
	g.Commit()
	g.Push()
}
