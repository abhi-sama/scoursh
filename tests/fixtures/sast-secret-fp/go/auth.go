package auth

// Validator tags, not credentials.
var rules = map[string]string{
	"password": "required,min=12,max=128", // [[N26]]
	"apiKey":   "required,len=32,alphanum", // [[N27]]
}
