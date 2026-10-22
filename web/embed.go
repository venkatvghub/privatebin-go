// Package web holds the embedded front end: PrivateBin 2.1.0's Bootstrap 5
// interface (unmodified CSS, JavaScript, images and translations, see
// THIRD_PARTY_NOTICES.md) and the page template that stands in for its PHP one.
package web

import (
	"bytes"
	"crypto/sha512"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"
)

//go:embed index.html.tmpl openapi.yaml css js img i18n vendor swagger manifest.json browserconfig.xml robots.txt
var content embed.FS

// Version is the PrivateBin release the front end is copied from; it is the
// cache-busting suffix on asset URLs and shown in the footer.
const Version = "2.1.0"

// SyntaxThemes are the prettify themes shipped in css/prettify.
var SyntaxThemes = []string{"desert", "doxy", "sons-of-obsidian", "sunburst"}

func FS() fs.FS { return content }

// IndexData fills the page template.
type IndexData struct {
	Name        string
	Info        template.HTML // trusted operator text shown in the footer, may hold links
	SyntaxTheme string        // one of SyntaxThemes, or empty for the default look
	AuthEnabled bool          // shows a "Log in" link
	// BurnAfterReading preselects the "Burn after reading" option; users can still untick it.
	BurnAfterReading bool
	// Status, Deleted and Error add the result of a delete link to the page.
	Status  string
	Deleted bool
	Error   string
}

// RenderIndex renders the page once. Every script and the module preload carry a
// Subresource Integrity hash computed from the embedded file.
func RenderIndex(d IndexData) ([]byte, error) {
	sri := func(name string) (string, error) {
		b, err := fs.ReadFile(content, name)
		if err != nil {
			return "", err
		}
		sum := sha512.Sum512(b)
		return "sha512-" + base64.StdEncoding.EncodeToString(sum[:]), nil
	}
	t, err := template.New("index.html.tmpl").Funcs(template.FuncMap{"sri": sri}).ParseFS(content, "index.html.tmpl")
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = t.Execute(&buf, struct {
		IndexData
		Version string
	}{d, Version})
	if err != nil {
		return nil, fmt.Errorf("render index: %w", err)
	}
	return buf.Bytes(), nil
}
