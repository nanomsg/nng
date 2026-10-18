// pubrefman renders an NNG 1.x AsciiDoc manual as a standalone web site.
//
// It intentionally contains no publishing or Git logic.  GitHub Actions owns
// checkout and deployment; this program retains the legacy tool's manual
// parsing and index-generation behavior.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type page struct {
	name        string
	section     string
	description string
	filename    string
}

type section struct {
	name        string
	synopsis    string
	description string
	pages       []page
}

func main() {
	sourceDir := flag.String("source-dir", "", "directory containing the AsciiDoc manpage sources")
	outputDir := flag.String("output-dir", "", "directory for the rendered manual")
	themeDir := flag.String("theme-dir", "", "directory containing nng-site-header.css and nng-site-header.js")
	version := flag.String("version", "", "major.minor documentation version")
	flag.Parse()

	if *sourceDir == "" || *outputDir == "" || *themeDir == "" || *version == "" {
		fatal("-source-dir, -output-dir, -theme-dir, and -version are required")
	}
	if !strings.HasPrefix(*version, "1.") {
		fatal("legacy documentation version must begin with 1.: %s", *version)
	}

	entries, err := os.ReadDir(*sourceDir)
	if err != nil {
		fatal("read source directory: %v", err)
	}
	if err = os.MkdirAll(*outputDir, 0o755); err != nil {
		fatal("create output directory: %v", err)
	}

	sections := map[string]*section{}
	pages := make([]page, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		switch {
		case strings.HasSuffix(name, ".sect"):
			sectionName := strings.TrimSuffix(strings.TrimPrefix(name, "man"), ".sect")
			synopsis := readFile(filepath.Join(*sourceDir, name))
			description := readFile(filepath.Join(*sourceDir, "man"+sectionName+".desc"))
			sections[sectionName] = &section{name: sectionName, synopsis: synopsis, description: description}
		case strings.HasSuffix(name, ".adoc"):
			p := parsePage(filepath.Join(*sourceDir, name))
			pages = append(pages, p)
		}
	}

	for _, p := range pages {
		s, ok := sections[p.section]
		if !ok {
			fatal("%s refers to missing section %s", p.filename, p.section)
		}
		s.pages = append(s.pages, p)
	}

	if err = copyTheme(*themeDir, *outputDir); err != nil {
		fatal("copy shared theme: %v", err)
	}

	for _, p := range pages {
		output := filepath.Join(*outputDir, strings.TrimSuffix(p.filename, ".adoc")+".html")
		render(filepath.Join(*sourceDir, p.filename), output)
		injectChrome(output)
	}

	indexSource := buildIndex(sections)
	renderSource(indexSource, filepath.Join(*outputDir, "index.html"))
	injectChrome(filepath.Join(*outputDir, "index.html"))

	fmt.Printf("Rendered NNG %s legacy manual: %d pages in %s\n", *version, len(pages), *outputDir)
}

func parsePage(filename string) page {
	source := readFile(filename)
	var description string
	inName := false
	for _, rawLine := range strings.Split(source, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "== NAME" {
			inName = true
			continue
		}
		if inName && line != "" {
			parts := strings.SplitN(line, " - ", 2)
			if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
				fatal("%s has a malformed NAME section", filename)
			}
			description = strings.TrimSpace(parts[1])
			break
		}
	}

	if description == "" {
		fatal("%s is missing a valid NAME section", filename)
	}
	// A few early 1.x pages have a typo in the NAME entry. The source file
	// name is the stable public identity used by cross-references and indexes.
	base := strings.TrimSuffix(filepath.Base(filename), ".adoc")
	separator := strings.LastIndex(base, ".")
	if separator < 1 || separator == len(base)-1 {
		fatal("%s does not have a manpage-style filename", filename)
	}
	name := base[:separator]
	sectionName := base[separator+1:]

	return page{name: name, section: sectionName, description: description, filename: filepath.Base(filename)}
}

func buildIndex(sections map[string]*section) string {
	sectionNames := make([]string, 0, len(sections))
	for name := range sections {
		sectionNames = append(sectionNames, name)
	}
	sort.Strings(sectionNames)

	var index strings.Builder
	index.WriteString("= NNG Reference Manual\n\n")
	for _, sectionName := range sectionNames {
		s := sections[sectionName]
		sort.Slice(s.pages, func(i, j int) bool { return s.pages[i].name < s.pages[j].name })
		fmt.Fprintf(&index, "== Section %s: %s\n\n", s.name, s.synopsis)
		index.WriteString(s.description)
		index.WriteString("\n\n[cols=\"3,5\"]\n|===\n")
		for _, p := range s.pages {
			fmt.Fprintf(&index, "|link:%s.%s.html[%s(%s)]\n|%s\n", p.name, p.section, p.name, p.section, p.description)
		}
		index.WriteString("|===\n\n")
	}
	return index.String()
}

func render(source, output string) {
	command := exec.Command("asciidoctor", "-a", "nofooter", "-a", "toc=left", "-a", "icons=font", "-d", "manpage", "-b", "html5", "-o", output, source)
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		fatal("render %s: %v", source, err)
	}
}

func renderSource(source, output string) {
	command := exec.Command("asciidoctor", "-a", "nofooter", "-a", "toc=left", "-a", "icons=font", "-d", "article", "-b", "html5", "-o", output, "-")
	command.Stdin = strings.NewReader(source)
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		fatal("render index: %v", err)
	}
}

func injectChrome(filename string) {
	contents := readFile(filename)
	chrome := "  <link rel=\"stylesheet\" href=\"theme/nng-site-header.css\">\n  <script defer src=\"theme/nng-site-header.js\"></script>\n"
	if !strings.Contains(contents, "</head>") {
		fatal("%s does not contain an HTML head", filename)
	}
	contents = strings.Replace(contents, "</head>", chrome+"</head>", 1)
	writeFile(filename, contents)
}

func copyTheme(themeDir, outputDir string) error {
	targetDir := filepath.Join(outputDir, "theme")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"nng-site-header.css", "nng-site-header.js"} {
		source, err := os.Open(filepath.Join(themeDir, name))
		if err != nil {
			return err
		}
		target, err := os.Create(filepath.Join(targetDir, name))
		if err != nil {
			source.Close()
			return err
		}
		_, copyErr := io.Copy(target, source)
		closeErr := target.Close()
		source.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func readFile(filename string) string {
	contents, err := os.ReadFile(filename)
	if err != nil {
		fatal("read %s: %v", filename, err)
	}
	return string(contents)
}

func writeFile(filename, contents string) {
	if err := os.WriteFile(filename, []byte(contents), 0o644); err != nil {
		fatal("write %s: %v", filename, err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pubrefman: "+format+"\n", args...)
	os.Exit(1)
}
