package main

import (
	"net/http"
	"text/template"
)

// handler renders HTML to an http.ResponseWriter using text/template,
// which performs no contextual auto-escaping - true positive for
// SAST-GO-TEMPLATE_HTML-01.
func handler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("page").Parse("<h1>{{.Name}}</h1>"))
	tmpl.Execute(w, r.URL.Query().Get("name"))
}
