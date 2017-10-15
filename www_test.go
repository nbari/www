package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestCreateSSL(t *testing.T) {
	certPEMBlock, keyPEMBlock, err := createSSL()

	if certPEMBlock == nil {
		t.Errorf("Error when create ssl %v", err)
	}

	if keyPEMBlock == nil {
		t.Errorf("Error when create ssl %v", err)
	}

	if err != nil {
		t.Errorf("Error when create ssl %v", err)
	}
}

func TestMain(t *testing.T) {
	// Create a request to pass to www handler.
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	r := "." // current dir
	q := false

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.Handler(www(r, q))

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	expected := "www.go"
	re := regexp.MustCompile("www.go")
	isContains := re.MatchString(rr.Body.String())
	if !isContains {
		t.Errorf("handler returned unexpected body: got %v but not contains %v",
			rr.Body.String(), expected)
	}
}
