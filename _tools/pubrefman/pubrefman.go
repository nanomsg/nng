// Copyright 2020 Staysail Systems, Inc.
//
// Provided under...
//

package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
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
)

var version string
var debug bool
var repo string
var email string
var name string
var dryRun bool

func init() {
	flag.StringVar(&version, "v", "tip", "Version to publish")
	flag.BoolVar(&debug, "d", false, "Enable debugging")
	flag.BoolVar(&dryRun, "N", false, "Dry run, does not push changes")
	flag.StringVar(&repo, "r", "ssh://git@github.com/nanomsg/nng.git", "Repo to publish from")
	flag.StringVar(&email, "e", "info@staysail.tech", "Email to commit using")
	flag.StringVar(&name, "n", "Staysail Systems, Inc.", "Name to commit using")
}
func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	if debug {
		panic("Failed")
	}
	os.Exit(1)
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
	SrcFs    billy.Filesystem
	DstFs    billy.Filesystem
	DstDir   string
	Tag      string
	LaConfig configuration.Configuration
	Sections map[string]*Section
	Pages    map[string]*Page
	Repo     *git.Repository
	Index    string
	ToC      string
	Added    map[string]bool
	WorkTree *git.Worktree
	Branch   string
}

func (g *Global) Init() {
	g.Sections = make(map[string]*Section)
	g.Pages = make(map[string]*Page)
	g.Added = make(map[string]bool)
	g.SrcFs = memfs.New()
	g.DstFs = memfs.New()
	g.Tag = version
	g.DstDir = path.Join("man", g.Tag)
	g.LaConfig = configuration.Configuration{
		AttributeOverrides: map[string]string{
			"nofooter":           "yes",
			"icons":              "font",
			"linkcss":            "yes",
			"source-highlighter": "pygments",
		},
	}
}

func (g *Global) Destroy() {
}

func (g *Global) Debug(format string, args ...interface{}) {
	if !debug {
		return
	}
	out := &strings.Builder{}
	out.WriteString("DEBUG: ")
	_, _ = fmt.Fprintf(out, format, args...)
	_, _ = fmt.Println(out.String())

}

func (g *Global) CloneSource() {
	tag := g.Tag
	if tag == "" || tag == "tip" {
		tag = "master"
	}
	ref := plumbing.NewBranchReferenceName(tag)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	now := time.Now()
	_, err := git.CloneContext(ctx, memory.NewStorage(), g.SrcFs, &git.CloneOptions{
		URL:           repo,
		ReferenceName: ref,
	})
	g.Debug("Cloned source (%s) in %v", tag, time.Since(now))
	if err != nil {
		fatal(err)
	}
}

func (g *Global) ClonePages() {
	ref := plumbing.NewBranchReferenceName("gh-pages")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	now := time.Now()
	repo, err := git.CloneContext(ctx, memory.NewStorage(), g.DstFs, &git.CloneOptions{
		URL:           repo,
		ReferenceName: ref,
		RemoteName:    "origin",
	})
	g.Repo = repo
	g.Debug("Cloned pages in %v", time.Since(now))
	if err != nil {
		fatal(err)
	}
}

func (g *Global) PostProcessHTML(html string, version string, title string) string {
	// skip everything leading up to the opening body tag
	result := &strings.Builder{}

	_, _ = fmt.Fprintln(result, "---")
	_, _ = fmt.Fprintf(result, "version: %s\n", version)
	_, _ = fmt.Fprintf(result, "layout: %s\n", "manpage_v2")
	_, _ = fmt.Fprintf(result, "title: %s\n", title)
	_, _ = fmt.Fprintln(result, "---")
	_, _ = fmt.Fprint(result, html)
	return result.String()
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
				fatal(fmt.Errorf("page %s NAME malformed", page.Name()))
			}
			name = w[0]
			desc = w[1]
			strings.TrimSpace(name)
			strings.TrimSpace(desc)
			break
		}
	}

	if desc == "" {
		fatal(fmt.Errorf("page %s NAME missing", page.Name()))
	}

	html := &strings.Builder{}

	// Emit the title, as we are not letting libasciidoc do it (stripping headers)
	cfg := g.LaConfig
	cfg.Filename = page.Name()
	cfg.LastUpdated = page.ModTime()
	metadata, err := libasciidoc.Convert(strings.NewReader(source), html, cfg)
	if err != nil {
		fatal(fmt.Errorf("error processing %s: %w", page.Name(), err))
	}
	w := strings.SplitN(metadata.Title, "(", 2)
	sect := strings.TrimSuffix(w[1], ")")
	if len(w) != 2 || name != w[0] || !strings.HasSuffix(w[1], ")") {
		fatal(fmt.Errorf("page %s title incorrect (%s)", page.Name(), name))
	}
	if page.Name() != name+"."+sect+".adoc" {
		fatal(fmt.Errorf("page %s(%s) does not match file name %s", name, sect, page.Name()))
	}
	result := &strings.Builder{}
	_, _ = fmt.Fprintf(result, "---\n")
	_, _ = fmt.Fprintf(result, "version: %s\n", g.Tag)
	_, _ = fmt.Fprintf(result, "layout: %s\n", "manpage_v2")
	_, _ = fmt.Fprintf(result, "---\n")
	_, _ = fmt.Fprintf(result, "<h1>%s(%s)</h1>\n", name, sect)
	result.WriteString(html.String())

	g.Pages[page.Name()] = &Page{
		Name:        name,
		Section:     sect,
		Description: desc,
		Content:     result.String(),
	}
}

func (g *Global) ReadFile(name string) string {
	f, err := g.SrcFs.Open(path.Join("docs/man", name))
	if err != nil {
		fatal(err)
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		fatal(err)
	}
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
	if err != nil {
		fatal(err)
	}
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
		sect := g.Sections[page.Section]
		if sect == nil {
			fatal(fmt.Errorf("page %s section %s not found", page.Name, page.Section))
		}
		sect.Pages = append(sect.Pages, page)
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
	_, _ = fmt.Fprintf(index, "version: %s\n", g.Tag)
	_, _ = fmt.Fprintf(index, "layout: %s\n", "manpage_v2")
	_, _ = fmt.Fprintf(index, "---\n")
	_, _ = fmt.Fprintf(index, "<h1>NNG Reference Manual</h1>\n")

	cfg := g.LaConfig
	cfg.Filename = "index.adoc"
	if _, err := libasciidoc.Convert(strings.NewReader(idx.String()), index, cfg); err != nil {
		fatal(err)
	}
	g.Index = index.String()
	g.ToC = toc.String()
}

func (g *Global) CreateBranch() {
	brName := uuid.New().String()
	var err error

	refName := plumbing.ReferenceName("refs/heads/" + brName)
	g.Branch = brName

	g.WorkTree, err = g.Repo.Worktree()
	if err != nil {
		fatal(err)
	}

	g.WorkTree.Checkout(&git.CheckoutOptions{
		Branch: refName,
		Create: true,
	})
	g.Debug("Branch name will be %v", brName)
}

func (g *Global) WriteFile(name string, content string) {
	full := path.Join(g.DstDir, name)
	f, err := g.DstFs.Create(full)
	if err != nil {
		fatal(err)
	}
	if _, err = f.Write([]byte(content)); err != nil {
		fatal(err)
	}
	if err = f.Close(); err != nil {
		fatal(err)
	}
	g.Add(name)
}

func (g *Global) Add(name string) {
	g.Added[name] = true
}

func (g *Global) Delete(name string) {
	_, err := g.WorkTree.Remove(path.Join(g.DstDir, name))
	if err != nil {
		fatal(err)
	}
}

func (g *Global) Commit() {
	_, err := g.WorkTree.Commit("Changes for "+g.Tag, &git.CommitOptions{
		Author: &object.Signature{
			Email: email,
			Name:  name,
			When:  time.Now(),
		},
	})
	if err != nil {
		fatal(err)
	}
}

func (g *Global) Push() {
	err := g.Repo.Push(&git.PushOptions{
		RemoteName: "origin",
	})
	if err != nil {
		fatal(err)
	}
	fmt.Printf("Pushed branch %v\n", g.Branch)
}

func (g *Global) WriteOutput() {

	for _, p := range g.Pages {
		fName := fmt.Sprintf("%s.%s.html", p.Name, p.Section)
		g.WriteFile(fName, p.Content)
	}
	g.WriteFile("_toc.html", g.ToC)
	g.WriteFile("index.html", g.Index)

	g.WorkTree.Add(g.DstDir)
	files, err := g.DstFs.ReadDir(g.DstDir)
	if err != nil {
		fatal(err)
	}
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
	if err != nil {
		fatal(err)
	}
	if status.IsClean() {
		fmt.Println("No changes to commit.")
		os.Exit(0)
	}
	g.Debug(status.String())
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
	if !dryRun {
		g.Push()
	}
}
