package main

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
)

//go:embed assets/page.html assets/page.css assets/page.js
var defaultPageFiles embed.FS

const (
	pageHTMLName = "page.html"
	pageCSSName  = "page.css"
	pageJSName   = "page.js"
)

type pageRenderer struct {
	template *template.Template
	css      string
	js       string
}

type pageData struct {
	CSS template.CSS
	JS  template.JS
}

func loadPage(dir string) (*pageRenderer, error) {
	html, css, js, err := readPageFiles(dir)
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("page").Parse(string(html))
	if err != nil {
		return nil, errors.New("the page template is invalid")
	}
	return &pageRenderer{template: tmpl, css: string(css), js: string(js)}, nil
}

func readPageFiles(dir string) ([]byte, []byte, []byte, error) {
	if dir == "" {
		html, err := defaultPageFiles.ReadFile("assets/" + pageHTMLName)
		if err != nil {
			return nil, nil, nil, err
		}
		css, err := defaultPageFiles.ReadFile("assets/" + pageCSSName)
		if err != nil {
			return nil, nil, nil, err
		}
		js, err := defaultPageFiles.ReadFile("assets/" + pageJSName)
		if err != nil {
			return nil, nil, nil, err
		}
		return html, css, js, nil
	}
	html, err := os.ReadFile(filepath.Join(dir, pageHTMLName))
	if err != nil {
		return nil, nil, nil, errors.New("LAUNCH_PAGE_DIR must contain page.html")
	}
	css, err := readOptionalPageFile(dir, pageCSSName)
	if err != nil {
		return nil, nil, nil, err
	}
	js, err := readOptionalPageFile(dir, pageJSName)
	if err != nil {
		return nil, nil, nil, err
	}
	return html, css, js, nil
}

func readOptionalPageFile(dir, name string) ([]byte, error) {
	content, err := os.ReadFile(filepath.Join(dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read %s", name)
	}
	return content, nil
}

func cspHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func (p *pageRenderer) serve(w http.ResponseWriter, r *http.Request) {
	policy := "default-src 'none'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	if p.css != "" {
		policy += "; style-src " + cspHash(p.css)
	}
	if p.js != "" {
		policy += "; script-src " + cspHash(p.js)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", policy)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_ = p.template.Execute(w, pageData{CSS: template.CSS(p.css), JS: template.JS(p.js)})
}
