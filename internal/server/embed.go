package server

import "embed"

//go:embed templates/*.html static/*.css
var embedFS embed.FS
