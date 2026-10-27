package main
import "text/template"
func page(w http.ResponseWriter,r *http.Request) { template.Must(template.New("x").Parse("{{.}}")).Execute(w,r.URL.Query().Get("q")) }
