package auth

import "net/http"

func HelloHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	_, _ = w.Write([]byte("Hello from auth!"))
}
