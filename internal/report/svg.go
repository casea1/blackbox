package report

import (
	"fmt"
	"html/template"
	"math"
	"strings"
)

// Charts are drawn as inline SVG when the report is written, so they need
// no script and print as they look.

const (
	colAccent   = "#0B5FFF"
	colBad      = "#D12C2C"
	colWarn     = "#E08A00"
	colLight    = "#7FA6E8"
	colGrid     = "rgba(0,30,98,.08)"
	fillAccent  = "rgba(11,95,255,.10)"
	fillBad     = "rgba(209,44,44,.10)"
	missingMark = -1
)

// sparkline draws vals (missing values are -1) as a line with a dot on the
// last value.
func sparkline(vals []int, bad bool, w, h int) template.HTML {
	color, fill := colAccent, fillAccent
	if bad {
		color, fill = colBad, fillBad
	}
	var pts [][2]float64
	mx, mn := math.Inf(-1), math.Inf(1)
	for _, v := range vals {
		if v == missingMark {
			continue
		}
		mx, mn = math.Max(mx, float64(v)), math.Min(mn, float64(v))
	}
	if len(vals) < 2 || math.IsInf(mx, -1) {
		return ""
	}
	span := mx - mn
	if span == 0 {
		span = 1
	}
	n := len(vals)
	for i, v := range vals {
		if v == missingMark {
			continue
		}
		x := float64(i)*float64(w-4)/float64(n-1) + 2
		y := float64(h-4) - (float64(v)-mn)/span*float64(h-10)
		pts = append(pts, [2]float64{x, y})
	}
	if len(pts) < 2 {
		return ""
	}
	var d strings.Builder
	for i, p := range pts {
		if i == 0 {
			fmt.Fprintf(&d, "M%.1f,%.1f", p[0], p[1])
		} else {
			fmt.Fprintf(&d, " L%.1f,%.1f", p[0], p[1])
		}
	}
	last := pts[len(pts)-1]
	area := fmt.Sprintf(`<path d="%s L%.1f,%d L%.1f,%d Z" fill="%s"/>`, d.String(), last[0], h, pts[0][0], h, fill)
	return template.HTML(fmt.Sprintf(`<svg width="%d" height="%d" viewBox="0 0 %d %d" aria-hidden="true">%s<path d="%s" fill="none" stroke="%s" stroke-width="1.6" stroke-linejoin="round"/><circle cx="%.1f" cy="%.1f" r="2.6" fill="%s"/></svg>`,
		w, h, w, h, area, d.String(), color, last[0], last[1], color))
}

// Series is one stacked part of a bar chart.
type Series struct {
	Name   string
	Values []int
	Color  string
}

// niceMax rounds a chart's top value up to 1, 2 or 5 × a power of ten.
func niceMax(v float64) float64 {
	if v <= 0 {
		return 1
	}
	p := math.Pow(10, math.Floor(math.Log10(v)))
	for _, m := range []float64{1, 2, 5, 10} {
		if v <= m*p {
			return m * p
		}
	}
	return 10 * p
}

// stackedBars draws one bar per label, stacked by series. hot marks bars
// outlined in red (above normal); faded draws all but the last bar faded.
func stackedBars(labels []string, series []Series, hot []bool, faded bool, w, h int) template.HTML {
	n := len(labels)
	if n == 0 {
		return ""
	}
	tot := make([]int, n)
	top := 0
	for _, s := range series {
		for i, v := range s.Values {
			tot[i] += v
		}
	}
	for _, v := range tot {
		if v > top {
			top = v
		}
	}
	mx := niceMax(float64(top) * 1.05)
	x0, bw := 34.0, float64(w-34)/float64(n)
	plot := float64(h - 34)
	// Only as many day labels as fit (about 6.5 units a letter at 11px).
	step, long := 1, 0
	for i, l := range labels {
		if faded && i == n-1 && n > 1 {
			continue // the last is always shown, from its right edge
		}
		long = max(long, len(l))
	}
	if bw < 6.5*float64(long)+8 {
		step = int(math.Ceil((6.5*float64(long) + 8) / bw))
	}
	var b strings.Builder
	for _, v := range []float64{0, mx / 2, mx} {
		y := float64(h-22) - v/mx*plot
		fmt.Fprintf(&b, `<line x1="%.0f" x2="%d" y1="%.1f" y2="%.1f" stroke="%s"/><text x="%.0f" y="%.1f" text-anchor="end" class="ax">%s</text>`,
			x0, w, y, y, colGrid, x0-6, y+4, shortNum(v))
	}
	for i := 0; i < n; i++ {
		x, bwid := x0+float64(i)*bw+bw*.22, bw*.56
		y := float64(h - 22)
		op := "1"
		if faded && i < n-1 {
			op = ".5"
		}
		for _, s := range series {
			if i >= len(s.Values) || s.Values[i] <= 0 {
				continue
			}
			hh := float64(s.Values[i]) / mx * plot
			y -= hh
			fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s" opacity="%s"/>`, x, y, bwid, hh, s.Color, op)
		}
		if i < len(hot) && hot[i] && tot[i] > 0 {
			fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="none" stroke="%s" stroke-width="1.5"/>`, x-3, y-3, bwid+6, float64(h-22)-y+3, colBad)
		}
		weight := ""
		if faded && i == n-1 {
			weight = ` style="font-weight:700;fill:#0B1630"`
		}
		// Skip a label that would run off the right edge, or into the
		// last one.
		lastW := 0.0
		if faded {
			lastW = 6.5 * float64(len(labels[n-1]))
		}
		lx := x + bwid/2
		switch {
		case faded && i == n-1:
			anchor := "middle"
			if lx+lastW/2 > float64(w) {
				lx, anchor = float64(w), "end"
			}
			fmt.Fprintf(&b, `<text x="%.1f" y="%d" text-anchor="%s" class="ax"%s>%s</text>`, lx, h-6, anchor, weight, template.HTMLEscapeString(labels[i]))
		case i%step == 0 && lx+3.25*float64(len(labels[i])) <= float64(w)-lastW-6:
			fmt.Fprintf(&b, `<text x="%.1f" y="%d" text-anchor="middle" class="ax"%s>%s</text>`, lx, h-6, weight, template.HTMLEscapeString(labels[i]))
		}
	}
	return template.HTML(fmt.Sprintf(`<svg viewBox="0 0 %d %d" width="100%%" role="img">%s</svg>`, w, h, b.String()))
}

// weekBars draws twelve weekly bars with a dashed line at the average of
// the earlier weeks; this week is in full colour, and red when well above
// average. Missing weeks (-1) are left empty.
func weekBars(vals []int, labels []string, badWhenHigh bool, w, h int) template.HTML {
	n := len(vals)
	if n == 0 {
		return ""
	}
	top, sum, cnt := 0, 0, 0
	for i, v := range vals {
		if v > top {
			top = v
		}
		if i < n-1 && v >= 0 {
			sum += v
			cnt++
		}
	}
	mx := float64(top) * 1.15
	if mx == 0 {
		mx = 1
	}
	bw := float64(w-4) / float64(n)
	var b strings.Builder
	avg := -1.0
	if cnt > 0 {
		avg = float64(sum) / float64(cnt)
	}
	for i, v := range vals {
		if v < 0 {
			continue
		}
		bh := float64(v) / mx * float64(h-20)
		x := 4 + float64(i)*bw + bw*.18
		col, op := colAccent, ".35"
		if i == n-1 {
			op = "1"
			if badWhenHigh && avg >= 0 && float64(v) > avg*1.4 && v > 0 {
				col = colBad
			}
		}
		fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s" opacity="%s"/>`, x, float64(h-14)-bh, bw*.64, bh, col, op)
	}
	if avg >= 0 {
		ya := float64(h-14) - avg/mx*float64(h-20)
		fmt.Fprintf(&b, `<line x1="0" x2="%d" y1="%.1f" y2="%.1f" stroke="#0A2A7A" stroke-dasharray="3 3" opacity=".6"/>`, w, ya, ya)
	}
	if len(labels) == n {
		fmt.Fprintf(&b, `<text x="2" y="%d" class="ax">%s</text>`, h-2, template.HTMLEscapeString(labels[0]))
	}
	fmt.Fprintf(&b, `<text x="%d" y="%d" text-anchor="end" class="ax" style="font-weight:700;fill:#0B1630">This week</text>`, w-2, h-2)
	return template.HTML(fmt.Sprintf(`<svg viewBox="0 0 %d %d" width="100%%">%s</svg>`, w, h, b.String()))
}

func shortNum(v float64) string {
	switch {
	case v >= 1e6:
		return fmt.Sprintf("%.1fM", v/1e6)
	case v >= 1e4:
		return fmt.Sprintf("%.0fk", v/1e3)
	}
	return fmt.Sprintf("%.0f", v)
}
