package main

import (
	"bufio"
	"os"
	"strings"
)

func dofile(file string) {
	f, err := os.Open(file)
	out := &strings.Builder{}
	if err != nil {
		panic(err)
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "//"):
			continue
		case strings.HasPrefix(line, "= "):
			continue
		case strings.HasPrefix(line, "[.text-left]"):
			continue
		case strings.HasPrefix(line, "[source, c]"):
			out.WriteString("```c\n")
			scanner.Scan() // eat the next line
			continue
		case line == "----":
			out.WriteString("```\n")
			continue
		case line == "== NAME":
			out.Reset()
			scanner.Scan()
			scanner.Scan()
			parts := strings.SplitN(scanner.Text(), " - ", 2)
			out.WriteString("## ")
			out.WriteString(parts[0])
			out.WriteString("\n")
			line = parts[1]
			out.WriteString("\n")
			out.WriteString(strings.ToUpper(line[0:1]))
			out.WriteString(line[1:])
			out.WriteString(".\n")
		case strings.HasPrefix(line, "== "):
			out.WriteString("### ")
			out.WriteString(strings.Title(strings.ToLower(line[3:])))
			out.WriteString("\n")
			continue
		case strings.HasPrefix(line, "=== "):
			out.WriteString("#### ")
			out.WriteString(line[4:])
			out.WriteString("\n")
			continue
		default:
			line = strings.Replace(line, "()`", "`", -1)
			line = strings.Replace(line, "()]", "]", -1)
			line = strings.Replace(line, "(3)]", "]", -1)
			line = strings.Replace(line, "(5)]", "]", -1)
			line = strings.Replace(line, "(7)]", "]", -1)
			line = strings.Replace(line, "(3compat)]", "]", -1)
			line = strings.Replace(line, "(3http)]", "]", -1)
			line = strings.Replace(line, "(3str)]", "]", -1)
			line = strings.Replace(line, "(3supp)]", "]", -1)
			line = strings.Replace(line, "(3tls)]", "]", -1)
			line = strings.Replace(line, ".3.adoc", ".adoc", -1)
			line = strings.Replace(line, ".5.adoc", ".adoc", -1)
			line = strings.Replace(line, ".7.adoc", ".adoc", -1)
			line = strings.Replace(line, ".3compat.adoc", ".adoc", -1)
			line = strings.Replace(line, ".3http.adoc", ".adoc", -1)
			line = strings.Replace(line, ".3str.adoc", ".adoc", -1)
			line = strings.Replace(line, ".3supp.adoc", ".adoc", -1)
			line = strings.Replace(line, ".3tls.adoc", ".adoc", -1)
			out.WriteString(line)
			out.WriteRune('\n')
			continue
		}
	}
	tmpFile := file + "tmp"
	var w *os.File
	w, err = os.Create(tmpFile)
	if _, err = w.WriteString(out.String()); err != nil {
		os.Remove(tmpFile)
	} else {
		os.Rename(tmpFile, file)
	}
}

func main() {
	for _, arg := range os.Args {
		dofile(arg)
	}
}
