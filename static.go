package main

import (
	"log"
	"net/http"

	"github.com/nbari/violetear"
)

func main() {
	router := violetear.New()
	router.LogRequests = true
	router.Handle("*", http.StripPrefix("/", http.FileServer(http.Dir("."))))
	log.Fatal(http.ListenAndServe(":8000", router))
}
