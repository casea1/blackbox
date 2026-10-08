package report

import (
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/store"
)

// DESIGN1: on a collector's report, each system's page says how its
// data came ("Delivery: signed · key SHA256:ab12… since 8 Oct"), Needs
// attention names new, changed, held and unsigned senders, and the
// Verified pop-up says whether every delivery was signed.
func TestDeliveryInReport(t *testing.T) {
	end := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	since := time.Date(2026, 10, 8, 14, 2, 0, 0, time.UTC)
	fp := "SHA256:ab12cd34ef56gh78ij90kl12mn34op56qr78st90uv1"
	run := func(h string) *store.Run { return &store.Run{Time: end.Add(-time.Hour), Host: h, OS: "windows"} }
	opts := func(sys ...SystemInfo) Options {
		return Options{WindowStart: end.AddDate(0, 0, -7), WindowEnd: end, Generated: end, Location: time.UTC, Collector: true, Systems: sys}
	}
	signed := func(h string, d *Delivery) SystemInfo {
		return SystemInfo{Name: h, OS: "windows", LastRun: end.Add(-time.Hour), LastReceived: end.Add(-time.Hour), Delivery: d}
	}
	all := Build(nil, []*store.Run{run("WS-01"), run("COL")}, opts(signed("WS-01", &Delivery{Signed: true, KeyFP: fp, Since: since}), signed("COL", nil)))
	sp := all.systemsPage()
	got, level := "", "x"
	for _, g := range sp.Groups {
		for _, v := range g.Systems {
			if v.Name == "WS-01" {
				got, level = v.Delivery, v.DelivLevel
			}
		}
	}
	if got != "Delivery: signed · key SHA256:ab12cd34… since 8 Oct" || level != "" {
		t.Errorf("system page: %q %q", got, level)
	}
	var html strings.Builder
	if err := all.WriteHTML(&html, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html.String(), `<div class="sysdeliv ">Delivery: signed · key SHA256:ab12cd34… since 8 Oct</div>`) {
		t.Error("the one-system page lacks its Delivery line")
	}
	if l, ok := all.deliveryVerifyLine(); !ok || l.Text != "All deliveries were signed by their computer's key" {
		t.Errorf("Verified: %+v %v", l, ok)
	}
	if ls := all.deliveryCheckLines(); len(ls) != 1 || ls[0].Level != "ok" {
		t.Errorf("all signed: %+v", ls)
	}

	mixed := Build(nil, nil, opts(
		signed("WS-01", &Delivery{Signed: true, KeyFP: fp, Since: since, NewKeyFP: "SHA256:cd34"}),
		signed("WS-02", &Delivery{Signed: true, KeyFP: fp, Since: since, New: true}),
		signed("ubu-ws-03", &Delivery{}),
		signed("WS-04", &Delivery{Signed: true, KeyFP: fp, Since: since, Held: true})))
	text := ""
	for _, l := range mixed.deliveryCheckLines() {
		text += l.Level + " " + l.Title + ": " + l.Who + " " + l.What + "\n"
	}
	for _, want := range []string{"bad Senders waiting for a decision", "blackbox senders rekey WS-01", "blackbox senders approve WS-04",
		"warn New senders", "WS-02 (SHA256:ab12cd34…)", "warn Unsigned senders: ubu-ws-03", "upgrade these to 0.24"} {
		if !strings.Contains(text, want) {
			t.Errorf("Needs attention lacks %q:\n%s", want, text)
		}
	}
	// On the redesigned pages: Overview's Needs attention names the
	// systems, and each one's page shows its line in the problem's colour.
	attn := map[string]AttnLine{}
	for _, l := range mixed.overview(nil).Attention {
		attn[l.Title] = l
	}
	for title, want := range map[string]string{
		"Senders waiting for a decision": "bad|WS-01, WS-04",
		"New senders":                    "warn|WS-02",
		"Unsigned senders":               "warn|ubu-ws-03",
	} {
		if l := attn[title]; l.Level+"|"+l.Count != want || l.Reason == "" || !strings.HasPrefix(l.Href, "#systems") {
			t.Errorf("Needs attention %q: %+v", title, l)
		}
	}
	if h := attn["New senders"].Href; h != "#systems/WS-02" {
		t.Errorf("one new sender links to %q", h)
	}
	levels := map[string]string{}
	for _, g := range mixed.systemsPage().Groups {
		for _, v := range g.Systems {
			levels[v.Name] = v.DelivLevel
		}
	}
	if levels["WS-01"] != "bad" || levels["WS-04"] != "bad" || levels["WS-02"] != "" || levels["ubu-ws-03"] != "warn" {
		t.Errorf("Delivery line levels: %v", levels)
	}
	if l, _ := mixed.deliveryVerifyLine(); !strings.Contains(l.File, "not signed: ubu-ws-03") || l.Bad {
		t.Errorf("Verified: %+v", l)
	}
	// Not a collector: nothing about deliveries.
	solo := Build(nil, nil, Options{WindowEnd: end, Location: time.UTC})
	if _, ok := solo.deliveryVerifyLine(); ok || len(solo.deliveryCheckLines()) != 0 {
		t.Error("a standalone report talks about deliveries")
	}
}
