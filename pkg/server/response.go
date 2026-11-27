package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/mirrorz-org/mirrorz-302/pkg/mirrorzdb"
	"github.com/mirrorz-org/mirrorz-302/pkg/requestmeta"
	"github.com/mirrorz-org/mirrorz-302/pkg/scoring"
)

// redirectResponse owns the HTTP result of a mirror lookup. The format is
// negotiated once and never affects which diagnostics the resolver records.
type redirectResponse struct {
	json         bool
	traceEnabled bool
	trace        *redirectTrace
	location     string
	errStatus    int
	errMessage   string
}

func newRedirectResponse(r *http.Request, query redirectQuery, queryErr error) redirectResponse {
	response := redirectResponse{
		json:         acceptsJSON(r.Header.Values("Accept")),
		traceEnabled: query.traceEnabled,
	}
	if queryErr != nil {
		response.errStatus, response.errMessage = http.StatusBadRequest, "invalid nth query"
	}
	return response
}

func (response *redirectResponse) traceContext(r *http.Request, meta requestmeta.RequestMeta, nth int) context.Context {
	if !response.traceEnabled {
		return r.Context()
	}
	response.trace = newRedirectTrace(r, meta, nth)
	return context.WithValue(r.Context(), redirectTraceKey{}, response.trace)
}

func (response *redirectResponse) setResolution(query redirectQuery, target string, err error) {
	switch {
	case errors.Is(err, ErrNthOutOfRange):
		if query.nth != 0 {
			response.errStatus, response.errMessage = http.StatusUnprocessableEntity, ErrNthOutOfRange.Error()
		} else {
			response.errStatus, response.errMessage = http.StatusNotFound, "No mirror sites are available for this repository"
		}
	case errors.Is(err, ErrInvalidPath):
		response.errStatus, response.errMessage = http.StatusBadRequest, "Invalid repository path"
	case err != nil:
		response.errStatus, response.errMessage = http.StatusServiceUnavailable, "Mirror information is temporarily unavailable"
	case target == "":
		response.errStatus, response.errMessage = http.StatusNotFound, "No mirror sites are available for this repository"
	default:
		response.location = target
		if query.rawQuery != "" {
			response.location += "?" + query.rawQuery
		}
	}
}

func (response redirectResponse) write(s *Server, w http.ResponseWriter, r *http.Request) {
	if response.traceEnabled {
		w.Header().Set("Cache-Control", "no-store")
	} else if response.errStatus == 0 {
		http.Redirect(w, r, response.location, http.StatusFound)
		return
	}

	// Plaintext traces retain their legacy 200 response for resolution failures,
	// except for out-of-range positive nth. JSON errors never return a partial trace.
	if response.errStatus != 0 && (response.json || response.trace == nil || response.errStatus == http.StatusUnprocessableEntity) {
		writeResponseError(w, response.json, response.errStatus, response.errMessage)
		return
	}

	var err error
	if response.json {
		body, marshalErr := json.Marshal(response.trace)
		if marshalErr != nil {
			s.errorLogger.Errorf("Error encoding redirect trace: %v", marshalErr)
			writeResponseError(w, response.json, http.StatusInternalServerError, "Could not encode redirect trace")
			return
		}
		w.Header().Add("Vary", "Accept")
		setJSONHeaders(w)
		_, err = w.Write(append(body, '\n'))
	} else {
		w.Header().Add("Vary", "Accept")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, err = io.WriteString(w, response.trace.plaintext(response.errMessage))
	}
	if err != nil {
		s.errorLogger.Errorf("Error writing redirect trace: %v", err)
	}
}

type redirectTraceKey struct{}

type redirectTrace struct {
	Request struct {
		Path          string   `json:"path"`
		CanonicalPath string   `json:"canonical_path"`
		Labels        []string `json:"labels"`
		IP            *string  `json:"ip"`
		Region        string   `json:"region"`
		ISP           []string `json:"isp"`
		Scheme        string   `json:"scheme"`
		Nth           int      `json:"nth"`
	} `json:"request"`
	OutdatedThresholds struct {
		Dynamic  int `json:"dynamic"`
		Absolute int `json:"absolute"`
	} `json:"outdated_thresholds"`
	Conventions struct {
		PlusInfinity *float64 `json:"plus_infinity"`
	} `json:"conventions"`
	Mirrors []traceMirror      `json:"mirrors"`
	Scores  []rankedTraceScore `json:"scores"`
	Result  struct {
		Nth    int    `json:"nth"`
		Abbr   string `json:"abbr"`
		Tail   string `json:"tail"`
		Target string `json:"target"`
	} `json:"result"`

	privateScores map[traceEndpointKey]struct{}
}

type traceEndpointKey struct{ abbr, label, resolve string }

type traceMirror struct {
	Abbr      string             `json:"abbr"`
	Endpoints []traceEndpoint    `json:"endpoints"`
	Scores    []rankedTraceScore `json:"scores"`
}

type traceEndpoint struct {
	Label       string      `json:"label,omitempty"`
	Resolve     string      `json:"resolve,omitempty"`
	RangeRegion *[]string   `json:"range_region,omitempty"`
	RangeISP    *[]string   `json:"range_isp,omitempty"`
	Score       *traceScore `json:"score,omitempty"`
	Error       string      `json:"error,omitempty"`
}

type rankedTraceScore struct {
	Rank  int        `json:"rank"`
	Score traceScore `json:"score"`
}

type traceScore struct {
	Pos           int      `json:"pos"`
	Mask          int      `json:"mask"`
	Geo           *float64 `json:"geo"`
	ISP           int      `json:"isp"`
	Delta         int      `json:"delta"`
	Label         *string  `json:"label"`
	Resolve       *string  `json:"resolve"`
	Repo          *string  `json:"repo"`
	UnknownStatus bool     `json:"unknown_status"`
}

func newRedirectTrace(r *http.Request, meta requestmeta.RequestMeta, nth int) *redirectTrace {
	t := &redirectTrace{Mirrors: []traceMirror{}, Scores: []rankedTraceScore{}}
	t.Request.Path = r.URL.EscapedPath()
	t.Request.Labels = append([]string{}, meta.Labels...)
	if len(meta.IP) != 0 {
		ip := meta.IP.String()
		t.Request.IP = &ip
	}
	t.Request.Region = meta.Region
	t.Request.ISP = append([]string{}, meta.ISP...)
	t.Request.Scheme = meta.Scheme
	t.Request.Nth = nth
	return t
}

func currentRedirectTrace(ctx context.Context) *redirectTrace {
	t, _ := ctx.Value(redirectTraceKey{}).(*redirectTrace)
	return t
}

func (t *redirectTrace) addMirror(abbr string) *traceMirror {
	t.Mirrors = append(t.Mirrors, traceMirror{Abbr: abbr, Endpoints: []traceEndpoint{}, Scores: []rankedTraceScore{}})
	return &t.Mirrors[len(t.Mirrors)-1]
}

func (m *traceMirror) addEndpoint(endpoint mirrorzdb.Endpoint) *traceEndpoint {
	e := traceEndpoint{}
	if endpoint.Public {
		e.Label, e.Resolve = endpoint.Label, endpoint.Resolve
		region, isp := append([]string{}, endpoint.RangeRegion...), append([]string{}, endpoint.RangeISP...)
		e.RangeRegion, e.RangeISP = &region, &isp
	}
	m.Endpoints = append(m.Endpoints, e)
	return &m.Endpoints[len(m.Endpoints)-1]
}

func newTraceScore(s scoring.Score, public bool) traceScore {
	score := traceScore{Pos: s.Pos, Mask: s.Mask, ISP: s.ISP, Delta: s.Delta, UnknownStatus: s.Unknown}
	if !math.IsInf(s.Geo, 0) && !math.IsNaN(s.Geo) {
		score.Geo = &s.Geo
	}
	if public {
		score.Label, score.Resolve, score.Repo = &s.Label, &s.Resolve, &s.Repo
	}
	return score
}

func (t *redirectTrace) rank(scores scoring.Scores) []rankedTraceScore {
	ranked := make([]rankedTraceScore, len(scores))
	for i, score := range scores {
		_, private := t.privateScores[traceEndpointKey{score.Abbr, score.Label, score.Resolve}]
		ranked[i] = rankedTraceScore{Rank: i, Score: newTraceScore(score, !private)}
	}
	return ranked
}

func (t *redirectTrace) recordScore(endpoint *traceEndpoint, score scoring.Score, public bool) {
	record := newTraceScore(score, public)
	endpoint.Score = &record
	if !public {
		if t.privateScores == nil {
			t.privateScores = make(map[traceEndpointKey]struct{})
		}
		t.privateScores[traceEndpointKey{score.Abbr, score.Label, score.Resolve}] = struct{}{}
	}
}

func (t *redirectTrace) plaintext(message string) string {
	var body strings.Builder
	fmt.Fprintf(&body, "Request path: %s; canonical path: %s\n", t.Request.Path, t.Request.CanonicalPath)
	fmt.Fprintf(&body, "Labels: %v\nIP: %s %s %v\nScheme: %s\nRequested nth=%d\n",
		t.Request.Labels, displayTraceValue(t.Request.IP), t.Request.Region, t.Request.ISP, t.Request.Scheme, t.Request.Nth)
	fmt.Fprintf(&body, "outdated thresholds: dynamic=%d absolute=%d\n", t.OutdatedThresholds.Dynamic, t.OutdatedThresholds.Absolute)
	for _, mirror := range t.Mirrors {
		fmt.Fprintf(&body, "abbr: %s\n", mirror.Abbr)
		for _, endpoint := range mirror.Endpoints {
			if endpoint.RangeRegion == nil {
				fmt.Fprintln(&body, "  endpoint: private")
			} else {
				fmt.Fprintf(&body, "  endpoint: %s %s %v %v\n", endpoint.Resolve, endpoint.Label, *endpoint.RangeRegion, *endpoint.RangeISP)
			}
			if endpoint.Score != nil {
				fmt.Fprintf(&body, "    score: %s\n", *endpoint.Score)
			} else if endpoint.Error != "" {
				fmt.Fprintf(&body, "    error: %s\n", endpoint.Error)
			}
		}
		writeTextRanks(&body, "  ", mirror.Scores)
	}
	writeTextRanks(&body, "", t.Scores)
	if t.Result.Target != "" {
		fmt.Fprintf(&body, "nth=%d site=%s; tail: %s; target: %s\n", t.Result.Nth, t.Result.Abbr, t.Result.Tail, t.Result.Target)
	}
	if message != "" {
		fmt.Fprintf(&body, "error: %s\n", message)
	}
	return body.String()
}

func writeTextRanks(w io.Writer, indent string, scores []rankedTraceScore) {
	if len(scores) == 0 {
		fmt.Fprintf(w, "%sno score available\n", indent)
	}
	for _, ranked := range scores {
		fmt.Fprintf(w, "%sscore %d: %s\n", indent, ranked.Rank, ranked.Score)
	}
}

func displayTraceValue(value *string) string {
	if value == nil {
		return "-"
	}
	return *value
}

func (score traceScore) String() string {
	geo := "-"
	if score.Geo != nil {
		geo = strconv.FormatFloat(*score.Geo, 'g', -1, 64)
	}
	return fmt.Sprintf("pos=%d mask=%d geo=%s isp=%d delta=%d label=%s resolve=%s repo=%s unknown_status=%t",
		score.Pos, score.Mask, geo, score.ISP, score.Delta, displayTraceValue(score.Label),
		displayTraceValue(score.Resolve), displayTraceValue(score.Repo), score.UnknownStatus)
}

func acceptsJSON(values []string) bool {
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(item))
			if err != nil || mediaType != "application/json" {
				continue
			}
			if quality, ok := params["q"]; ok {
				q, err := strconv.ParseFloat(quality, 64)
				if err != nil || !(q > 0 && q <= 1) {
					continue
				}
			}
			return true
		}
	}
	return false
}

func writeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	writeResponseError(w, acceptsJSON(r.Header.Values("Accept")), status, message)
}

func writeResponseError(w http.ResponseWriter, asJSON bool, status int, message string) {
	w.Header().Add("Vary", "Accept")
	if !asJSON {
		http.Error(w, message, status)
		return
	}

	setJSONHeaders(w)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: message})
}

func setJSONHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}
