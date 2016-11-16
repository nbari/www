package www

import (
	"fmt"
	"net/http"

	"github.com/nbari/violetear"
)

type WWW struct {
	port int
	root string
	log  bool
}

func New(p int, r string, s bool) error {
	router := violetear.New()
	router.Verbose = !s
	router.LogRequests = !s
	router.Handle("*",
		http.StripPrefix("/",
			http.FileServer(http.Dir(r)),
		),
	)
	return http.ListenAndServe(fmt.Sprintf(":%d", p), router)
}
