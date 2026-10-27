package main
import "text/template"
// ResponseWriter appears in API documentation.
var t = template.Must(template.New("mail").Parse("plain text"))
