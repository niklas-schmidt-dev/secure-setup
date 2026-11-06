package runner

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"time"
)

var localTailscaleCandidates = []string{
	"tailscale",
	"/usr/local/bin/tailscale",
	"/Applications/Tailscale.app/Contents/MacOS/Tailscale",
	"/opt/homebrew/bin/tailscale",
}

// LocalTailscaleReady reports whether this machine's Tailscale client is
// connected, with a human explanation when it is not.
func LocalTailscaleReady(ctx context.Context) (bool, string) {
	bin := ""
	for _, c := range localTailscaleCandidates {
		if p, err := exec.LookPath(c); err == nil {
			bin = p
			break
		}
		if _, err := os.Stat(c); err == nil {
			bin = c
			break
		}
	}
	if bin == "" {
		return false, "The tailscale command was not found on this computer. Install Tailscale from https://tailscale.com/download and log in."
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, bin, "status", "--json").Output()
	if err != nil {
		return false, "Tailscale is installed but not running on this computer (" + bin + " status failed). Start the Tailscale app or run `tailscale up`."
	}
	var st struct {
		BackendState string `json:"BackendState"`
	}
	if err := json.Unmarshal(out, &st); err != nil || st.BackendState != "Running" {
		state := st.BackendState
		if state == "" {
			state = "unknown"
		}
		return false, "Tailscale on this computer is in state " + state + ". Connect it (Tailscale menu > Connect, or `tailscale up`)."
	}
	return true, ""
}
