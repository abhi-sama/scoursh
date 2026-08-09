package main

import (
	"crypto/tls"
	"net/http"
)

// newClient disables TLS certificate verification outright - true
// positive for SAST-GO-TLS_SKIP_VERIFY-01.
func newClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}
