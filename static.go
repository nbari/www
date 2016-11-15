package main

import (
	"log"
	"net/http"

	"github.com/nbari/violetear"
)

func catchAll(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, r.URL.Path[1:])
}

func main() {
	router := violetear.New()
	router.LogRequests = true
	router.HandleFunc("*", catchAll)
	log.Fatal(http.ListenAndServe(":8000", router))
}
