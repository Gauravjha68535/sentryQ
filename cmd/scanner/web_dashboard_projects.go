package main

import (
	"net/http"
	"strconv"
)

// handleProjects returns a summary of every unique scan target (project),
// ordered by most-recently-scanned. Used by the Projects dashboard page.
//
// GET /api/projects
func handleProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := GetProjects()
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if projects == nil {
		projects = []ProjectSummary{}
	}
	httpJSON(w, http.StatusOK, projects)
}

// handleProjectTrend returns the time-series finding counts for a single project.
// Used to render the trend chart on the Projects page.
//
// GET /api/projects/trend?target=<encoded>&limit=<n>
func handleProjectTrend(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		httpJSON(w, http.StatusBadRequest, map[string]string{"error": "target query param required"})
		return
	}
	limit := 30
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	points, err := GetProjectTrend(target, limit)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if points == nil {
		points = []TrendPoint{}
	}
	httpJSON(w, http.StatusOK, points)
}
