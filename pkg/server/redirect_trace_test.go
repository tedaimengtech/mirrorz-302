package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func traceRequest(s *Server, path, accept string) *httptest.ResponseRecorder {
	r := mirrorlistRequest(http.MethodGet, path)
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestJSONRedirectTrace(t *testing.T) {
	var queries atomic.Int32
	s, closeServer := newMirrorlistTestServer(t, 300, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		queries.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// Use the same delta for both sites so the path rejection is visible.
		_, _ = w.Write([]byte(strings.Replace(mirrorlistInfluxResponse, `,-2,false`, `,-1,false`, 1)))
	}))
	defer closeServer()
	patchRedirectSite(t, s, "tuna", map[string]any{"redirects": map[string]any{
		"repo": map[string]any{"rewrite": []map[string]string{{"match": `^/(.*)$`, "target": `/debian/${1}`}}},
	}})
	patchRedirectSite(t, s, "ustc", map[string]any{"redirects": map[string]any{
		"repo": map[string]any{"blacklist": []string{`^/file$`}},
	}})
	require.NoError(t, os.WriteFile(filepath.Join(s.mirrorzdDir, "sites", "global.json"),
		[]byte(`{"redirects":[{"match":"^/alias(/.*)$","target":"/repo${1}"}]}`), 0600))
	require.NoError(t, s.LoadMirrorZD())

	ordinary := traceRequest(s, "/alias/file?token=x%2Fy&nth=1", "application/json")
	require.Equal(t, http.StatusFound, ordinary.Code)
	assert.Equal(t, "https://generic.example.com/repo/debian/file?token=x%2Fy", ordinary.Header().Get("Location"))

	w := traceRequest(s, "/alias/file?token=x%2Fy&trace=1&nth=1", "application/json")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "Accept", w.Header().Get("Vary"))
	assert.Empty(t, w.Header().Get("Location"))
	assert.NotContains(t, w.Body.String(), "token")
	assert.NotContains(t, w.Body.String(), `^/file$`)
	assert.NotContains(t, w.Body.String(), `"score_fields"`)
	assert.Contains(t, w.Body.String(), `"unknown_status":false`)
	assert.Contains(t, w.Body.String(), `"geo":null`)
	assert.EqualValues(t, 2, queries.Load(), "JSON tracing bypasses the fresh cache")

	var trace redirectTrace
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &trace))
	assert.Equal(t, "/alias/file", trace.Request.Path)
	assert.Equal(t, "/repo/file", trace.Request.CanonicalPath)
	assert.Equal(t, 1, trace.Request.Nth)
	assert.Equal(t, 1, trace.Result.Nth)
	assert.Equal(t, "TUNA", trace.Result.Abbr)
	assert.Equal(t, "/debian/file", trace.Result.Tail)
	assert.Equal(t, "https://generic.example.com/repo/debian/file", trace.Result.Target)
	require.Len(t, trace.Scores, 2)
	assert.Equal(t, 1, trace.Scores[1].Rank)
	require.NotNil(t, trace.Scores[1].Score.Resolve)
	assert.Equal(t, "generic.example.com", *trace.Scores[1].Score.Resolve)
	mirrors := make(map[string]traceMirror)
	for _, mirror := range trace.Mirrors {
		mirrors[mirror.Abbr] = mirror
	}
	require.Len(t, mirrors["TUNA"].Scores, 2)
	assert.Equal(t, trace.Scores, mirrors["TUNA"].Scores)
	require.Len(t, mirrors["USTC"].Endpoints, 1)
	assert.Equal(t, "path blacklist[0]", mirrors["USTC"].Endpoints[0].Error)
	assert.NotNil(t, mirrors["USTC"].Scores, "empty lists serialize as arrays")
	assert.Empty(t, mirrors["USTC"].Scores)

	for _, accept := range []string{"", "application/json;q=0"} {
		text := traceRequest(s, "/alias/file?token=x%2Fy&trace=1&nth=1", accept)
		assert.Equal(t, http.StatusOK, text.Code)
		assert.Equal(t, "text/plain; charset=utf-8", text.Header().Get("Content-Type"))
		assert.Equal(t, "Accept", text.Header().Get("Vary"))
		assert.Equal(t, "no-store", text.Header().Get("Cache-Control"))
		assert.Empty(t, text.Header().Get("Location"))
		assert.Contains(t, text.Body.String(), "path blacklist[0]")
		assert.Contains(t, text.Body.String(), "nth=1 site="+trace.Result.Abbr)
		assert.Contains(t, text.Body.String(), "target: "+trace.Result.Target)
		assert.NotContains(t, text.Body.String(), "token")
		assert.NotContains(t, text.Body.String(), `^/file$`)
	}
	assert.EqualValues(t, 4, queries.Load(), "plaintext tracing also bypasses the fresh cache")
}

func TestJSONRedirectTraceErrors(t *testing.T) {
	s, closeServer := newMirrorlistTestServer(t, 300, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query().Get("params")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(params, `"cname":"missing"`):
			_, _ = w.Write([]byte(`{"results":[{}]}`))
		case strings.Contains(params, `"cname":"offline"`):
			http.Error(w, "private backend detail", http.StatusBadGateway)
		default:
			_, _ = w.Write([]byte(mirrorlistInfluxResponse))
		}
	}))
	defer closeServer()

	for _, tc := range []struct {
		path, message string
		status        int
	}{
		{"/repo?nth=bad&trace=1", "invalid nth query", http.StatusBadRequest},
		{"/repo?trace=1&nth=bad", "invalid nth query", http.StatusBadRequest},
		{"/repo/%2e%2e/file?trace=1", "Invalid repository path", http.StatusBadRequest},
		{"/missing?trace=1", "No mirror sites are available for this repository", http.StatusNotFound},
		{"/repo?trace=1&nth=3", "nth out of range", http.StatusUnprocessableEntity},
		{"/offline?trace=1", "Mirror information is temporarily unavailable", http.StatusServiceUnavailable},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := traceRequest(s, tc.path, "application/json")
			assert.Equal(t, tc.status, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			assert.Equal(t, "Accept", w.Header().Get("Vary"))
			assert.Empty(t, w.Header().Get("Location"))
			assert.JSONEq(t, `{"error":"`+tc.message+`"}`, w.Body.String())

			text := traceRequest(s, tc.path, "application/json;q=0")
			status := tc.status
			if status != http.StatusUnprocessableEntity && !strings.Contains(tc.path, "nth=bad") {
				status = http.StatusOK // legacy plaintext trace with diagnostics
			}
			assert.Equal(t, status, text.Code)
			assert.Equal(t, "text/plain; charset=utf-8", text.Header().Get("Content-Type"))
			assert.Equal(t, "no-store", text.Header().Get("Cache-Control"))
			assert.Equal(t, "Accept", text.Header().Get("Vary"))
			assert.Contains(t, text.Body.String(), tc.message)
			assert.NotContains(t, text.Body.String(), "private backend detail")
		})
	}
	text := traceRequest(s, "/missing?trace=1", "text/plain")
	assert.Equal(t, http.StatusOK, text.Code, "legacy text trace keeps its status")
	assert.Contains(t, text.Body.String(), "no score available")
}

func TestJSONRedirectTraceRedactsPrivateEndpoint(t *testing.T) {
	s, closeServer := newMirrorlistTestServer(t, 300, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.Replace(mirrorlistInfluxResponse, `,-2,false`, `,0,false`, 1)))
	}))
	defer closeServer()
	patchRedirectSite(t, s, "ustc", map[string]any{"endpoints": []map[string]any{{
		"label": "hidden-label", "resolve": "hidden.example.com", "public": false,
		"filter": []string{"V4", "V6", "SSL", "NOSSL"}, "range": []string{"192.0.2.0/24"},
	}}})

	w := traceRequest(s, "/repo?trace=1", "application/json")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "hidden.example.com")
	assert.NotContains(t, w.Body.String(), "hidden-label")
	assert.NotContains(t, w.Body.String(), "192.0.2.0/24")
	text := traceRequest(s, "/repo?trace=1", "text/plain")
	require.Equal(t, http.StatusOK, text.Code, text.Body.String())
	assert.Contains(t, text.Body.String(), "endpoint: private")
	assert.NotContains(t, text.Body.String(), "hidden.example.com")
	assert.NotContains(t, text.Body.String(), "hidden-label")
	assert.NotContains(t, text.Body.String(), "192.0.2.0/24")
	var trace redirectTrace
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &trace))
	require.Len(t, trace.Scores, 3)
	var privateRank *rankedTraceScore
	for i := range trace.Scores {
		if trace.Scores[i].Score.Label == nil {
			privateRank = &trace.Scores[i]
		}
	}
	require.NotNil(t, privateRank)
	assert.Nil(t, privateRank.Score.Resolve)
	assert.Nil(t, privateRank.Score.Repo)
	assert.True(t, privateRank.Score.UnknownStatus)
	assert.Equal(t, 2, privateRank.Rank, "unknown status ranks after known status")
}
