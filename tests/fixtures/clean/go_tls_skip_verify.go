package main

import (
	"crypto/tls"
	"net/http"
)

// newClient leaves TLS certificate verification enabled - safe
// equivalent for SAST-GO-TLS_SKIP_VERIFY-01.
func newClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}
	return &http.Client{Transport: tr}
}
