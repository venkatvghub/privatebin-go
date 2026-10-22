package web

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

var localRef = regexp.MustCompile(`(?:src|href)="([^"#?]+)`)

// Every local file the page links to must exist in the embedded files, so a
// missing asset is a test failure, not a blank page.
func TestRenderedPageReferencesOnlyEmbeddedFiles(t *testing.T) {
	page, err := RenderIndex(IndexData{Name: "privatebin-go", SyntaxTheme: "desert", AuthEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	refs := localRef.FindAllStringSubmatch(string(page), -1)
	if len(refs) < 20 {
		t.Fatalf("found only %d asset references", len(refs))
	}
	for _, m := range refs {
		if strings.Contains(m[1], ":") || strings.HasPrefix(m[1], "auth/") { // external links, login route
			continue
		}
		if _, err := fs.Stat(content, m[1]); err != nil {
			t.Errorf("page references %q, which is not embedded: %v", m[1], err)
		}
	}
}

func TestRenderIndexOptions(t *testing.T) {
	base, _ := RenderIndex(IndexData{Name: "My Bin"})
	themed, _ := RenderIndex(IndexData{Name: "My Bin", SyntaxTheme: "sunburst", Info: `see <a href="/about">about</a>`, AuthEnabled: true})
	for name, tc := range map[string]struct {
		page string
		want []string
		not  []string
	}{
		"defaults": {string(base),
			[]string{"<title>My Bin</title>", `value="never"`, `value="1week" selected`, `id="burnafterreading"`, `value="markdown"`, `value="syntaxhighlighting"`, `css/prettify/prettify.css`, `integrity="sha512-`},
			[]string{"css/prettify/sunburst.css", "Log in"}},
		"options": {string(themed),
			[]string{"css/prettify/sunburst.css", "Log in", `see <a href="/about">about</a>`},
			nil},
	} {
		for _, w := range tc.want {
			if !strings.Contains(tc.page, w) {
				t.Errorf("%s: page lacks %q", name, w)
			}
		}
		for _, n := range tc.not {
			if strings.Contains(tc.page, n) {
				t.Errorf("%s: page must not contain %q", name, n)
			}
		}
	}
}

func TestBurnAfterReadingDefault(t *testing.T) {
	on, _ := RenderIndex(IndexData{Name: "x", BurnAfterReading: true})
	off, _ := RenderIndex(IndexData{Name: "x"})
	const checked = `id="burnafterreading" name="burnafterreading" checked="checked"`
	if !strings.Contains(string(on), checked) {
		t.Error("burn after reading must be preselected when it is the default")
	}
	if strings.Contains(string(off), checked) || !strings.Contains(string(off), `id="burnafterreading"`) {
		t.Error("burn after reading must be present but not preselected otherwise")
	}
}

func TestSyntaxThemesAreShipped(t *testing.T) {
	for _, name := range SyntaxThemes {
		if _, err := fs.Stat(content, "css/prettify/"+name+".css"); err != nil {
			t.Errorf("theme %s: %v", name, err)
		}
	}
}

// The copied interface files must stay byte-for-byte what was imported (see
// PROVENANCE.md): every recorded SHA-256 must match the embedded file.
func TestCopiedFilesMatchRecordedSums(t *testing.T) {
	for _, list := range []struct{ file, dir string }{
		{"PRIVATEBIN_FILES.sha256", ""},
		{"vendor/CHECKSUMS.txt", "vendor/"},
	} {
		f, err := content.Open(list.file)
		if err != nil {
			t.Fatalf("%s is not embedded: %v", list.file, err)
		}
		sc, checked := bufio.NewScanner(f), 0
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			sum, name, ok := strings.Cut(line, "  ")
			if !ok {
				t.Fatalf("%s: malformed line %q", list.file, line)
			}
			b, err := fs.ReadFile(content, list.dir+name)
			if err != nil {
				t.Errorf("%s lists %s, which is missing: %v", list.file, name, err)
				continue
			}
			if got := sha256.Sum256(b); hex.EncodeToString(got[:]) != sum {
				t.Errorf("%s changed: the copied files must stay unmodified", list.dir+name)
			}
			checked++
		}
		f.Close()
		if checked < 2 {
			t.Errorf("%s: only %d files checked", list.file, checked)
		}
	}
	for _, must := range []string{"js/privatebin.js", "js/legacy.js", "js/bootstrap-5.3.8.js", "js/prettify.js", "js/kjua-0.10.0.js"} {
		b, _ := fs.ReadFile(content, "PRIVATEBIN_FILES.sha256")
		if !strings.Contains(string(b), "  "+must) {
			t.Errorf("%s is not covered by PRIVATEBIN_FILES.sha256", must)
		}
	}
}
