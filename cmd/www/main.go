package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/nbari/violetear"
	"github.com/nbari/www"
)

var version string

func main() {
	var (
		p   = flag.Int("p", 8000, "Listen on `port`")
		r   = flag.String("r", ".", "document `root` path")
		s   = flag.Bool("s", false, "`silent` or quiet mode")
		ssl = flag.Bool("ssl", false, "use `SSL` https://")
		v   = flag.Bool("v", false, fmt.Sprintf("Print version: %s", version))
	)

	flag.Parse()

	if *v {
		fmt.Printf("%s\n", version)
		os.Exit(0)
	}

	err := www.CreateSSL()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
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

	// maybe a string so it could define the path of where to store the cert
	if *ssl {
		log.Fatal(http.ListenAndServeTLS(
			fmt.Sprintf(":%d", *p),
			".www.pem",
			".www.key",
			router),
		)
	} else {
		log.Fatal(http.ListenAndServe(
			fmt.Sprintf(":%d", *p),
			router),
		)
	}
}
