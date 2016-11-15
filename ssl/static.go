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
	err := http.ListenAndServeTLS(":8000", "server.pem", "server.key", router)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
