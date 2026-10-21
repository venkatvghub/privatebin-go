package web

import (
	"embed"
	"io/fs"
)

//go:embed index.html openapi.yaml css js vendor swagger favicon.svg
var content embed.FS

func FS() fs.FS { return content }
