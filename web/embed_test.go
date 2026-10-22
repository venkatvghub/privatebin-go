package web

import (
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
