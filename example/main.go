package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

// Greet greets the client in the language its Accept-Language header asks for.
func Greet(w http.ResponseWriter, r *http.Request) {
	langHeader := r.Header.Get("Accept-Language")
	lang := strings.TrimSpace(strings.Split(langHeader, ",")[0])

	var greeting string
	switch {
	case strings.HasPrefix(lang, "de"):
		greeting = "Hallo Welt"
	case strings.HasPrefix(lang, "fr"):
		greeting = "Bonjour le monde"
	default:
		greeting = "Hello World"
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(greeting))
}

func main() {
	addr := "127.0.0.1:8080"
	mux := http.NewServeMux()
	mux.HandleFunc("/", Greet)

	fmt.Printf("Listening on http://%s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}
