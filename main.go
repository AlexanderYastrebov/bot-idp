package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	address := withDefault(os.Getenv("ADDRESS"), ":4159")

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "I'm OK\n")
	})

	slog.Info("Listen", "address", address)
	http.ListenAndServe(address, nil)
}

func withDefault[T comparable](val, def T) T {
	var zero T
	if val == zero {
		return def
	}
	return val
}
