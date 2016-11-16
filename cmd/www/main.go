package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/nbari/www"
)

func exit1(err error) {
	fmt.Println(err)
	os.Exit(1)
}

var version string

func main() {
	var (
		p = flag.Int("p", 8000, "Listen on `port`")
		r = flag.String("r", ".", "document `root` path")
		s = flag.Bool("s", false, "`silent` or quiet mode")
		v = flag.Bool("v", false, fmt.Sprintf("Print version: %s", version))
	)

	flag.Parse()

	if *v {
		fmt.Printf("%s\n", version)
		os.Exit(0)
	}

	err := www.New(*p, *r, *s)
	if err != nil {
		exit1(err)
	}
	log.Println(err)
}
