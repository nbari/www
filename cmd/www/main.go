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
		r   = flag.String("r", ".", "Document `root` path")
		s   = flag.Bool("s", false, "`silent` or quiet mode")
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
	router.Verbose = !*s
	router.LogRequests = !*s
	router.Handle("*",
		http.StripPrefix("/",
			http.FileServer(http.Dir(*r)),
		),
	)

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
