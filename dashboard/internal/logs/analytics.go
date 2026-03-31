package logs

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// DashboardAnalytics is aggregated data for the main dashboard UI.
type DashboardAnalytics struct {
	Range        string    `json:"range"`
	WindowStart  time.Time `json:"window_start"`
	WindowEnd    time.Time `json:"window_end"`
	Summary      DashboardSummary `json:"summary"`
	TimeSeries   DashboardTimeSeries `json:"time_series"`
	UserClients  []LabelCount `json:"user_clients"`
	RespStatus   []LabelCount `json:"response_status"`
	Referers     []BarRow `json:"referers"`
	VHosts       []BarRow `json:"vhosts"`
	GeoRequests  []BarRow `json:"geo_requests"`
	GeoBlocked   []BarRow `json:"geo_blocked"`
}

type DashboardSummary struct {
	ActiveHosts     int     `json:"active_hosts"`
	UniqueIPs       int     `json:"unique_ips"`
	RequestCount    int     `json:"request_count"`
	BlockedCount    int     `json:"blocked_count"`
	QPSAvg          float64 `json:"qps_avg"`
	Error4xx        int     `json:"error_4xx"`
	Error4xxRate    float64 `json:"error_4xx_rate"`
	Blocked4xx      int     `json:"blocked_4xx"`
	Blocked4xxRate  float64 `json:"blocked_4xx_rate"`
	Error5xx        int     `json:"error_5xx"`
	Error5xxRate    float64 `json:"error_5xx_rate"`
}

type DashboardTimeSeries struct {
	Labels    []string  `json:"labels"`
	Requests  []int     `json:"requests"`
	Blocked   []int     `json:"blocked"`
	QPSBars   []float64 `json:"qps_bars"`
}

type LabelCount struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

type BarRow struct {
	Label string  `json:"label"`
	Count int     `json:"count"`
	Pct   float64 `json:"pct"`
}

// BuildDashboardAnalytics filters entries to [windowStart, now) and aggregates.
func BuildDashboardAnalytics(entries []map[string]any, windowStart, windowEnd time.Time, rangeKey string) DashboardAnalytics {
	out := DashboardAnalytics{
		Range:       rangeKey,
		WindowStart: windowStart.UTC(),
		WindowEnd:   windowEnd.UTC(),
	}
	var filtered []map[string]any
	for _, e := range entries {
		t := parseEntryTime(e)
		if t.IsZero() {
			continue
		}
		if t.Before(windowStart) || !t.Before(windowEnd) {
			continue
		}
		filtered = append(filtered, e)
	}
	// chronological for bucketing
	sort.Slice(filtered, func(i, j int) bool {
		return parseEntryTime(filtered[i]).Before(parseEntryTime(filtered[j]))
	})

	n := len(filtered)
	total := float64(n)
	if total == 0 {
		out.TimeSeries = emptyTimeSeries(rangeKey, windowStart, windowEnd)
		return out
	}

	ipSet := make(map[string]struct{})
	uaCounts := make(map[string]int)
	statusCounts := make(map[string]int)
	refCounts := make(map[string]int)
	vhostCounts := make(map[string]int)
	geoReqCounts := make(map[string]int)
	geoBlkCounts := make(map[string]int)

	var err4xx, blocked4xx, err5xx, blockedTotal int
	for _, e := range filtered {
		ip := str(e["remote_addr"])
		if ip != "" {
			ipSet[ip] = struct{}{}
		}
		h := str(e["host"])
		st := statusCode(e["status"])
		if st >= 400 {
			blockedTotal++
		}
		cc := normalizeCountryCode(str(e["country"]))
		if cc != "" {
			geoReqCounts[cc]++
			if st >= 400 {
				geoBlkCounts[cc]++
			}
		}
		if st >= 400 && st < 500 {
			err4xx++
			if st == 403 || st == 401 || st == 429 || st == 406 {
				blocked4xx++
			}
		}
		if st >= 500 && st < 600 {
			err5xx++
		}
		sc := fmt.Sprintf("%d", st)
		if st == 0 {
			sc = "—"
		}
		statusCounts[sc]++

		ua := summarizeUA(str(e["user_agent"]))
		uaCounts[ua]++

		ref := normalizeReferer(str(e["referer"]))
		refCounts[ref]++

		if h != "" {
			vhostCounts[h]++
		}
	}

	durSec := windowEnd.Sub(windowStart).Seconds()
	if durSec < 1 {
		durSec = 1
	}
	qpsAvg := total / durSec

	out.Summary = DashboardSummary{
		UniqueIPs:    len(ipSet),
		RequestCount: n,
		BlockedCount: blockedTotal,
		QPSAvg:       math.Round(qpsAvg*1000) / 1000,
		Error4xx:     err4xx,
		Error4xxRate: math.Round((float64(err4xx)/total)*10000) / 10000,
		Blocked4xx:   blocked4xx,
		Blocked4xxRate: math.Round((float64(blocked4xx)/total)*10000) / 10000,
		Error5xx:     err5xx,
		Error5xxRate: math.Round((float64(err5xx)/total)*10000) / 10000,
	}

	out.TimeSeries = buildTimeSeries(filtered, rangeKey, windowStart, windowEnd)
	out.UserClients = topLabelCounts(uaCounts, 8)
	out.RespStatus = topLabelCounts(statusCounts, 12)
	out.Referers = topBarRows(refCounts, 10)
	out.VHosts = topBarRows(vhostCounts, 10)
	out.GeoRequests = topBarRowsWithTotal(geoReqCounts, n, 240)
	out.GeoBlocked = topBarRowsWithTotal(geoBlkCounts, blockedTotal, 240)

	return out
}

func emptyTimeSeries(rangeKey string, windowStart, windowEnd time.Time) DashboardTimeSeries {
	ts := DashboardTimeSeries{Labels: []string{}, Requests: []int{}, Blocked: []int{}, QPSBars: []float64{}}
	switch rangeKey {
	case "1h":
		for i := 0; i < 60; i++ {
			t := windowStart.Add(time.Duration(i) * time.Minute)
			ts.Labels = append(ts.Labels, t.UTC().Format("15:04"))
			ts.Requests = append(ts.Requests, 0)
			ts.Blocked = append(ts.Blocked, 0)
			ts.QPSBars = append(ts.QPSBars, 0)
		}
	case "6h":
		for i := 0; i < 72; i++ { // 6h / 5m buckets
			t := windowStart.Add(time.Duration(i*5) * time.Minute)
			ts.Labels = append(ts.Labels, t.UTC().Format("15:04"))
			ts.Requests = append(ts.Requests, 0)
			ts.Blocked = append(ts.Blocked, 0)
			ts.QPSBars = append(ts.QPSBars, 0)
		}
	case "7d":
		for d := 0; d < 7; d++ {
			t := windowStart.AddDate(0, 0, d)
			ts.Labels = append(ts.Labels, t.UTC().Format("Jan 02"))
			ts.Requests = append(ts.Requests, 0)
			ts.Blocked = append(ts.Blocked, 0)
			ts.QPSBars = append(ts.QPSBars, 0)
		}
	case "30d":
		for d := 0; d < 30; d++ {
			t := windowStart.AddDate(0, 0, d)
			ts.Labels = append(ts.Labels, t.UTC().Format("Jan 02"))
			ts.Requests = append(ts.Requests, 0)
			ts.Blocked = append(ts.Blocked, 0)
			ts.QPSBars = append(ts.QPSBars, 0)
		}
	default:
		for i := 0; i < 24; i++ {
			t0 := windowStart.Add(time.Duration(i) * time.Hour)
			ts.Labels = append(ts.Labels, t0.UTC().Format("15:04"))
			ts.Requests = append(ts.Requests, 0)
			ts.Blocked = append(ts.Blocked, 0)
			ts.QPSBars = append(ts.QPSBars, 0)
		}
	}
	return ts
}

func buildTimeSeries(filtered []map[string]any, rangeKey string, windowStart, windowEnd time.Time) DashboardTimeSeries {
	var labels []string
	var bucket func(t time.Time) string
	var bucketOrder []string
	bucketReq := make(map[string]int)
	bucketBlk := make(map[string]int)

	switch rangeKey {
	case "1h":
		for i := 0; i < 60; i++ {
			key := fmt.Sprintf("%d", i)
			bucketOrder = append(bucketOrder, key)
			labels = append(labels, windowStart.Add(time.Duration(i)*time.Minute).UTC().Format("15:04"))
		}
		bucket = func(t time.Time) string {
			if t.Before(windowStart) {
				return "0"
			}
			idx := int(t.Sub(windowStart) / time.Minute)
			if idx < 0 {
				idx = 0
			}
			if idx > 59 {
				idx = 59
			}
			return fmt.Sprintf("%d", idx)
		}
	case "6h":
		for i := 0; i < 72; i++ {
			key := fmt.Sprintf("%d", i)
			bucketOrder = append(bucketOrder, key)
			labels = append(labels, windowStart.Add(time.Duration(i*5)*time.Minute).UTC().Format("15:04"))
		}
		bucket = func(t time.Time) string {
			if t.Before(windowStart) {
				return "0"
			}
			idx := int(t.Sub(windowStart) / (5 * time.Minute))
			if idx < 0 {
				idx = 0
			}
			if idx > 71 {
				idx = 71
			}
			return fmt.Sprintf("%d", idx)
		}
	case "7d":
		for d := 0; d < 7; d++ {
			day := windowStart.AddDate(0, 0, d).UTC().Format("2006-01-02")
			bucketOrder = append(bucketOrder, day)
			labels = append(labels, windowStart.AddDate(0, 0, d).UTC().Format("Jan 02"))
		}
		bucket = func(t time.Time) string {
			if t.Before(windowStart) {
				return bucketOrder[0]
			}
			idx := int(t.Sub(windowStart) / (24 * time.Hour))
			if idx < 0 {
				idx = 0
			}
			if idx >= len(bucketOrder) {
				idx = len(bucketOrder) - 1
			}
			return bucketOrder[idx]
		}
	case "30d":
		for d := 0; d < 30; d++ {
			day := windowStart.AddDate(0, 0, d).UTC().Format("2006-01-02")
			bucketOrder = append(bucketOrder, day)
			labels = append(labels, windowStart.AddDate(0, 0, d).UTC().Format("Jan 02"))
		}
		bucket = func(t time.Time) string {
			if t.Before(windowStart) {
				return bucketOrder[0]
			}
			idx := int(t.Sub(windowStart) / (24 * time.Hour))
			if idx < 0 {
				idx = 0
			}
			if idx >= len(bucketOrder) {
				idx = len(bucketOrder) - 1
			}
			return bucketOrder[idx]
		}
	default: // rolling 24h in hourly buckets from windowStart
		for i := 0; i < 24; i++ {
			t0 := windowStart.Add(time.Duration(i) * time.Hour)
			key := fmt.Sprintf("%d", i)
			bucketOrder = append(bucketOrder, key)
			labels = append(labels, t0.UTC().Format("15:04"))
		}
		bucket = func(t time.Time) string {
			if t.Before(windowStart) {
				return "0"
			}
			idx := int(t.Sub(windowStart) / time.Hour)
			if idx < 0 {
				idx = 0
			}
			if idx > 23 {
				idx = 23
			}
			return fmt.Sprintf("%d", idx)
		}
	}

	for _, e := range filtered {
		t := parseEntryTime(e)
		if t.IsZero() {
			continue
		}
		b := bucket(t)
		bucketReq[b]++
		if statusCode(e["status"]) >= 400 {
			bucketBlk[b]++
		}
	}

	reqs := make([]int, len(bucketOrder))
	blk := make([]int, len(bucketOrder))
	qps := make([]float64, len(bucketOrder))
	secPer := 86400.0
	if rangeKey == "1h" {
		secPer = 60.0
	} else if rangeKey == "6h" {
		secPer = 300.0
	} else if rangeKey == "24h" || rangeKey == "" {
		secPer = 3600.0
	}
	for i, k := range bucketOrder {
		c := bucketReq[k]
		reqs[i] = c
		blk[i] = bucketBlk[k]
		qps[i] = math.Round(float64(c)/secPer*1000) / 1000
	}
	return DashboardTimeSeries{Labels: labels, Requests: reqs, Blocked: blk, QPSBars: qps}
}

