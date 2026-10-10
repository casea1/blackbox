package scap

import (
	"strings"
	"testing"
)

const td = "../../testdata/scap"

// SCC results (XCCDF 1.2 with the benchmark) and OpenSCAP ARF, found in
// their folders: newest and previous per computer and benchmark.
func TestFind(t *testing.T) {
	scans, notes := Find(td)
	if len(notes) != 0 {
		t.Errorf("notes: %v", notes)
	}
	if len(scans) != 2 {
		t.Fatalf("scans: %v", scans)
	}
	w := scans["WS-07|xccdf_mil.disa.stig_benchmark_MS_Windows_11_STIG"]
	if w == nil || w.Latest == nil || w.Previous == nil {
		t.Fatalf("WS-07: %+v", w)
	}
	l := w.Latest
	if l.Host != "WS-07" || l.Benchmark != "Microsoft Windows 11 Security Technical Implementation Guide" || l.Version != "V2R8" ||
		l.Profile != "I - Mission Critical Classified" || l.When().Format("2006-01-02") != "2026-09-29" || l.Score != 40 {
		t.Errorf("latest: %+v", l)
	}
	if l.Counts["pass"] != 2 || l.Counts["fail"] != 3 || len(l.Open) != 3 {
		t.Errorf("counts %v open %d", l.Counts, len(l.Open))
	}
	if c := l.OpenByCat(); c[1] != 1 || c[2] != 1 || c[3] != 1 {
		t.Errorf("by CAT: %v", c)
	}
	var cat1 Rule
	for _, o := range l.Open {
		if o.Cat() == 1 {
			cat1 = o
		}
	}
	if cat1.VulnID != "V-253254" || cat1.STIGID != "WN11-00-000005" || !strings.HasPrefix(cat1.Title, "Domain-joined systems") {
		t.Errorf("CAT I rule: %+v", cat1)
	}
	d, ok := w.Delta()
	if !ok || len(d.NewlyOpen) != 1 || d.NewlyOpen[0].STIGID != "WN11-CC-000005" || len(d.NewlyFixed) != 1 || d.NewlyFixed[0].STIGID != "WN11-00-000040" {
		t.Errorf("delta: %+v", d)
	}
	u := scans["UBU-01|xccdf_org.ssgproject.content_benchmark_UBUNTU2204"]
	if u == nil || u.Latest.Host != "ubu-01" || u.Latest.Benchmark != "Guide to the Secure Configuration of Ubuntu 22.04" ||
		!strings.Contains(u.Latest.Profile, "STIG") || len(u.Latest.Open) != 1 || u.Latest.Open[0].Cat() != 3 ||
		u.Latest.Open[0].Title != "Enable Auditing for Processes Which Start Prior to the Audit Daemon" || int(u.Latest.Score) != 66 {
		t.Errorf("ubuntu: %+v %+v", u.Latest, u.Latest.Open)
	}
}

func TestParseRejectsOtherXML(t *testing.T) {
	if _, err := Parse(strings.NewReader(`<config><item/></config>`)); err == nil {
		t.Error("not SCAP, no error")
	}
}

// SC1: OpenSCAP with SCAP Security Guide content gives no STIG ID in the
// rule result; the benchmark in the results file names it in a reference
// to the DISA STIG, next to the SRG ID.
func TestSSGStigIDFromReference(t *testing.T) {
	const x = `<?xml version="1.0"?>
<xccdf-1.2:Benchmark xmlns:xccdf-1.2="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.ssgproject.content_benchmark_UBUNTU2404">
  <xccdf-1.2:title>Guide to the Secure Configuration of Ubuntu 24.04</xccdf-1.2:title>
  <xccdf-1.2:version>0.1.81</xccdf-1.2:version>
  <xccdf-1.2:Group id="xccdf_org.ssgproject.content_group_fips">
    <xccdf-1.2:Rule id="xccdf_org.ssgproject.content_rule_is_fips_mode_enabled" severity="high">
      <xccdf-1.2:title>Verify '/proc/sys/crypto/fips_enabled' exists</xccdf-1.2:title>
      <xccdf-1.2:reference href="https://www.cyber.mil/stigs/srg-stig-tools">SRG-OS-000478-GPOS-00223</xccdf-1.2:reference>
      <xccdf-1.2:reference href="https://www.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux">UBTU-24-300028</xccdf-1.2:reference>
      <xccdf-1.2:reference href="https://www.cisecurity.org/benchmark/ubuntu_linux/">1.6.2</xccdf-1.2:reference>
    </xccdf-1.2:Rule>
  </xccdf-1.2:Group>
  <xccdf-1.2:TestResult id="xccdf_org.open-scap_testresult_stig" start-time="2026-10-05T00:17:00" end-time="2026-10-05T00:17:53">
    <xccdf-1.2:benchmark href="#xccdf_org.ssgproject.content_benchmark_UBUNTU2404"/>
    <xccdf-1.2:target>ubuntu-server</xccdf-1.2:target>
    <xccdf-1.2:rule-result idref="xccdf_org.ssgproject.content_rule_is_fips_mode_enabled" severity="high"><xccdf-1.2:result>fail</xccdf-1.2:result></xccdf-1.2:rule-result>
    <xccdf-1.2:score system="urn:xccdf:scoring:default" maximum="100">50</xccdf-1.2:score>
  </xccdf-1.2:TestResult>
</xccdf-1.2:Benchmark>`
	res, err := Parse(strings.NewReader(x))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || len(res[0].Open) != 1 {
		t.Fatalf("results: %+v", res)
	}
	if o := res[0].Open[0]; o.STIGID != "UBTU-24-300028" || o.Cat() != 1 {
		t.Errorf("open rule: %+v", o)
	}
}

// FIX1: a rule's fix text, and a complete fix script, are kept for the
// fix list.
func TestRuleFixText(t *testing.T) {
	const x = `<?xml version="1.0"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_t_benchmark_B">
  <Rule id="xccdf_t_rule_a" severity="high"><title>A</title>
    <fixtext>Configure the policy value for &quot;X&quot; to <xhtml:b xmlns:xhtml="http://www.w3.org/1999/xhtml">Enabled</xhtml:b>.</fixtext>
    <fix system="urn:xccdf:fix:script:sh">echo 1 &gt; /proc/x</fix>
  </Rule>
  <Rule id="xccdf_t_rule_b" severity="low"><title>B</title>
    <fix system="urn:xccdf:fix:script:sh">var=<sub idref="v"/></fix>
  </Rule>
  <TestResult id="xccdf_t_testresult_a" start-time="2026-10-05T00:17:00" end-time="2026-10-05T00:17:53">
    <target>h</target>
    <rule-result idref="xccdf_t_rule_a"><result>fail</result></rule-result>
    <rule-result idref="xccdf_t_rule_b"><result>fail</result></rule-result>
  </TestResult>
</Benchmark>`
	res, err := Parse(strings.NewReader(x))
	if err != nil {
		t.Fatal(err)
	}
	a, b := res[0].Open[0], res[0].Open[1]
	if a.FixText != `Configure the policy value for "X" to Enabled.` || a.Script != "echo 1 > /proc/x" || a.ScriptLang != "sh" {
		t.Errorf("rule a: %+v", a)
	}
	if b.Script != "" {
		t.Errorf("rule b's script needs values filled in: %q", b.Script)
	}
}
