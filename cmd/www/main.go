package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"

	"github.com/nbari/violetear"
	"github.com/nbari/www"
)

var version string

func main() {
	var (
		p   = flag.Int("p", 8000, "Listen on `port`")
		q   = flag.Bool("q", false, "`quiet` mode")
		r   = flag.String("r", ".", "Document `root` path")
		ssl = flag.Bool("ssl", false, "Enable `SSL` https://")
		v   = flag.Bool("v", false, fmt.Sprintf("Print version: %s", version))
	)

	flag.Parse()

	if *v {
		fmt.Printf("%s\n", version)
		os.Exit(0)
	}

	// start web server
	router := violetear.New()
	router.Verbose = false
	router.LogRequests = !*q
	router.Handle("*",
		http.StripPrefix("/",
			http.FileServer(http.Dir(*r)),
		),
	)

	// print port
	if !*q {
		log.Printf("Listening on port: %d\n", *p)
	}

	// enable ssl
	if *ssl {
		err := www.CreateSSL("/tmp")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		log.Fatal(http.ListenAndServeTLS(
			fmt.Sprintf(":%d", *p),
			path.Join("/tmp", ".www.pem"),
			path.Join("/tmp", ".www.key"),
			router),
		)
	} else {
		log.Fatal(http.ListenAndServe(
			fmt.Sprintf(":%d", *p),
			router),
		)
	}
}
