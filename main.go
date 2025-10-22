package main

import (
	"log"
	"net/http"

	"github.com/milanbella/sa-auth/auth"
)

func main() {
	router := newRouter()

	log.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatalf("http server failed: %v", err)
	}
}

func newRouter() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/hello", getHelloHandler)
	mux.HandleFunc("/auth/hello", auth.HelloHandler)

	return mux
}

func getHelloHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	_, _ = w.Write([]byte("Hello!"))
}
