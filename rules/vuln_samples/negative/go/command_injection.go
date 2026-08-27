package vulnsamples

import (
	"net/http"
	"os/exec"
)

//nolint:unused // vulnerability sample file
func safeRun(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	
	// Safe: fixed command with validated arg
	cmd := exec.Command("cat", filename)
	cmd.Run()
}
