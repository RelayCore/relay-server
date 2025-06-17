package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"relay-server/internal/util"
)

func getTenorClient() *util.Client {
    return util.NewClient()
}

func TenorSearchHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

	tenorClient := getTenorClient()
    if tenorClient == nil {
        http.Error(w, "Tenor API not configured", http.StatusServiceUnavailable)
        return
    }

    query := r.URL.Query().Get("q")
    if query == "" {
        http.Error(w, "Query parameter 'q' is required", http.StatusBadRequest)
        return
    }

    opts := util.SearchOptions{
        Query:         query,
        Limit:         20, // default
        Locale:        r.URL.Query().Get("locale"),
        ContentFilter: r.URL.Query().Get("contentfilter"),
        Pos:           r.URL.Query().Get("pos"),
    }

    if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
        if limit, err := strconv.Atoi(limitStr); err == nil {
            opts.Limit = limit
        }
    }

    results, err := tenorClient.Search(opts)
    if err != nil {
        http.Error(w, "Failed to search GIFs: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(results)
}

func TenorTrendingHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

	tenorClient := getTenorClient()
    if tenorClient == nil {
        http.Error(w, "Tenor API not configured", http.StatusServiceUnavailable)
        return
    }

    limit := 20 // default
    if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
        if l, err := strconv.Atoi(limitStr); err == nil {
            limit = l
        }
    }

    pos := r.URL.Query().Get("pos")

    results, err := tenorClient.GetTrending(limit, pos)
    if err != nil {
        http.Error(w, "Failed to get trending GIFs: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(results)
}

func TenorCategoriesHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

	tenorClient := getTenorClient()
    if tenorClient == nil {
        http.Error(w, "Tenor API not configured", http.StatusServiceUnavailable)
        return
    }

    categories, err := tenorClient.GetCategories()
    if err != nil {
        http.Error(w, "Failed to get categories: "+err.Error(), http.StatusInternalServerError)
        return
    }

    response := map[string]interface{}{
        "categories": categories,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}