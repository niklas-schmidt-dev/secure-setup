package localhost

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// WriteFile must create new directories 0700 and the file with its final
// mode, leaving no temporary file behind.
func TestWriteFileModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "var", "lib", "secure-setup")
	p := filepath.Join(dir, "tailscale.authkey")
	if err := (&Host{}).WriteFile(context.Background(), p, []byte("tskey-auth-DUMMY\n"), "0600"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %o, want 600", st.Mode().Perm())
	}
	dst, _ := os.Stat(dir)
	if dst.Mode().Perm() != 0o700 {
		t.Fatalf("new directory mode %o, want 700", dst.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover temp files: %v", entries)
	}
	// A world-readable file keeps its explicit mode.
	q := filepath.Join(dir, "cloudflare.nft")
	if err := (&Host{}).WriteFile(context.Background(), q, []byte("x\n"), "0644"); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(q); st.Mode().Perm() != 0o644 {
		t.Fatalf("0644 file got %o", st.Mode().Perm())
	}
}
