package main

import (
	"net/http"
	"html/template"
)

// handler renders the same HTML to an http.ResponseWriter using
// html/template, which auto-escapes untrusted values - safe equivalent
// for SAST-GO-TEMPLATE_HTML-01.
func handler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("page").Parse("<h1>{{.Name}}</h1>"))
	tmpl.Execute(w, r.URL.Query().Get("name"))
}
