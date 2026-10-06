package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/config"
)

// A first install writes every setting chosen in setup, archive_dir and
// scap_results included (the template's lines for them have no value, and
// a chosen archive_dir was lost); a re-install keeps the file's comments.
func TestWriteConfigFirstInstall(t *testing.T) {
	for _, crlf := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "blackbox.conf")
		opt := Options{Answers: Answers{Site: `Lab 3 "east"`, ReportEvery: "daily", ReportAt: config.DefaultReportAt, ReportDir: abs("/srv/reports"),
			ArchiveDir: abs("/data/logs"), CollectEvery: 15 * time.Minute, ScapResults: abs("/data/SCC/Sessions")}}
		if err := writeConfig(path, opt, crlf); err != nil {
			t.Fatal(err)
		}
		c, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if c.SiteName != `Lab 3 "east"` || c.ArchiveDir != abs("/data/logs") || c.ScapResults != abs("/data/SCC/Sessions") || c.ReportDir != abs("/srv/reports") || c.ReportEvery != "daily" {
			t.Errorf("crlf=%v: %+v", crlf, c)
		}
		b, _ := os.ReadFile(path)
		if !strings.Contains(string(b), "# ") || (crlf && !strings.Contains(string(b), "\r\n")) {
			t.Errorf("crlf=%v: the template's comments or line ends were lost", crlf)
		}
		// Upgrading with the same answers changes nothing.
		before := string(b)
		if err := writeConfig(path, opt, crlf); err != nil {
			t.Fatal(err)
		}
		if after, _ := os.ReadFile(path); string(after) != before {
			t.Errorf("crlf=%v: a re-install with the same settings changed the file", crlf)
		}
	}
}
