package vulnsamples

import (
	"fmt"
	"net/http"
	"os/exec"
)

//nolint:unused // vulnerability sample file
func runCmd(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	
	// Unsafe: fmt.Sprintf with user input
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ping %s", host))
	cmd.Run()
	
	// Unsafe: command with request param
	exec.Command("cat", r.FormValue("file")).Run()
}
