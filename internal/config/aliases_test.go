package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPeopleAliases(t *testing.T) {
	m, err := ParsePeopleAliases(` jlee = J.Lee, SRV-DC02\jlee2 ; mchen=m.chen`)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 || m["j.lee"] != "jlee" || m["jlee2"] != "jlee" || m["m.chen"] != "mchen" {
		t.Errorf("aliases: %v", m)
	}
	if got := FormatPeopleAliases(m); got != "jlee=j.lee,jlee2; mchen=m.chen" {
		t.Errorf("format: %q", got)
	}
	if m, err := ParsePeopleAliases(""); err != nil || m != nil {
		t.Errorf("empty: %v %v", m, err)
	}
	for _, bad := range []string{"jlee", "=j.lee", "jlee=", "jlee=a=b", "jlee=x; mchen=x", "jlee=x; jlee=y", "jlee=mchen; mchen=x"} {
		if _, err := ParsePeopleAliases(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// blackbox config set people_aliases "jlee=j.lee,jlee2"
	path := filepath.Join(t.TempDir(), "blackbox.conf")
	if err := SetValue(path, "people_aliases", "jlee=j.lee,jlee2"); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil || c.PeopleAliases["jlee2"] != "jlee" {
		t.Fatalf("loaded: %v %v", c.PeopleAliases, err)
	}
	if err := SetValue(path, "people_aliases", "jlee"); err == nil || !strings.Contains(err.Error(), "people_aliases") {
		t.Errorf("a bad value saved: %v", err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "people_aliases = jlee=j.lee,jlee2") {
		t.Errorf("file: %s", b)
	}
}
