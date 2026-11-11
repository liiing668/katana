package standard

import (
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/stretchr/testify/require"
)

// archiveTestServer returns a server where / links to /entry1 and /entry2,
// both of which redirect (302) to the same /target endpoint.
func archiveTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/entry1">one</a><a href="/entry2">two</a></body></html>`))
	})
	mux.HandleFunc("/entry1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	mux.HandleFunc("/entry2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	mux.HandleFunc("/target", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("target-body"))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

type collectedResults struct {
	mu      sync.Mutex
	results []output.Result
}

func (c *collectedResults) callback() types.OnResultCallback {
	return func(result output.Result) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.results = append(c.results, result)
	}
}

func (c *collectedResults) all() []output.Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]output.Result(nil), c.results...)
}

func newArchiveCrawlerOptions(t *testing.T, storeDir string, collected *collectedResults, mutate func(*types.Options)) *types.CrawlerOptions {
	t.Helper()
	opts := &types.Options{
		MaxDepth:            3,
		NoScope:             true,
		BodyReadSize:        math.MaxInt,
		Timeout:             10,
		Concurrency:         4,
		Parallelism:         1,
		Strategy:            "depth-first",
		StoreResponse:       true,
		StoreResponseDir:    storeDir,
		DisableUniqueFilter: true,
		OnResult:            collected.callback(),
	}
	if mutate != nil {
		mutate(opts)
	}
	crawlerOptions, err := types.NewCrawlerOptions(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = crawlerOptions.Close() })
	return crawlerOptions
}

// archiveFiles returns all archived response files below dir.
func archiveFiles(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	require.NoError(t, filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() != "index.txt" {
			files = append(files, path)
		}
		return nil
	}))
	return files
}

func indexLines(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "index.txt"))
	require.NoError(t, err)
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// TestStoreResponseArchiveLocalHTTP crawls a local server where multiple
// entries redirect to the same endpoint and verifies that every result is
// archived to its own file, that index/JSON paths point to the right
// response, and that counts and callbacks line up.
func TestStoreResponseArchiveLocalHTTP(t *testing.T) {
	server := archiveTestServer(t)
	storeDir := filepath.Join(t.TempDir(), "archive")
	collected := &collectedResults{}

	crawlerOptions := newArchiveCrawlerOptions(t, storeDir, collected, nil)
	crawler, err := New(crawlerOptions)
	require.NoError(t, err)
	defer func() { _ = crawler.Close() }()

	require.NoError(t, crawler.Crawl(server.URL))

	results := collected.all()
	require.NotEmpty(t, results)

	// Counts: callbacks, writer successes, index lines and files all agree.
	require.EqualValues(t, len(results), crawlerOptions.OutputWriter.GetResultCount())
	lines := indexLines(t, storeDir)
	require.Len(t, lines, len(results))
	files := archiveFiles(t, storeDir)
	require.Len(t, files, len(results))

	// Every published path is unique, exists on disk and holds the raw
	// request and final response of its own result.
	paths := map[string]bool{}
	for _, result := range results {
		require.NotNil(t, result.Response)
		path := result.Response.StoredResponsePath
		require.NotEmpty(t, path)
		require.False(t, paths[path], "stored response path %s published twice", path)
		paths[path] = true

		content, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Contains(t, string(content), result.Response.Raw)
		require.Contains(t, string(content), result.Request.Raw)
	}

	// Index paths point at the same files the JSON output published.
	for _, line := range lines {
		fields := strings.Fields(line)
		require.Len(t, fields, 4) // "<path> <url> (200 OK)"
		absPath, err := filepath.Abs(fields[0])
		require.NoError(t, err)
		require.True(t, paths[absPath], "index path %s was never published", fields[0])
		require.FileExists(t, fields[0])
	}

	// Both redirect entries land on /target: they must have produced two
	// distinct archive files for the same final URL.
	var targetPaths []string
	for _, result := range results {
		if result.Response.Resp != nil && result.Response.Resp.Request != nil &&
			result.Response.Resp.Request.URL.Path == "/target" && result.Request.URL != server.URL+"/target" {
			targetPaths = append(targetPaths, result.Response.StoredResponsePath)
		}
	}
	require.Len(t, targetPaths, 2, "expected both redirect entries to be archived")
	require.NotEqual(t, targetPaths[0], targetPaths[1])
}

// TestStoreResponseArchiveIOErrorPropagates injects an archive I/O failure
// (read-only host directory) and verifies the crawl reports it: Crawl
// returns an ErrStoreResponse-wrapping error, and the failed result is
// neither counted nor delivered to OnResult.
func TestStoreResponseArchiveIOErrorPropagates(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission-based fault injection is ineffective")
	}
	server := archiveTestServer(t)
	storeDir := filepath.Join(t.TempDir(), "archive")

	// Fault injection: pre-create the host subdirectory read-only so the
	// archive file creation fails mid-crawl.
	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)
	hostDir := filepath.Join(storeDir, strings.ReplaceAll(parsed.Host, ":", "_"))
	require.NoError(t, os.MkdirAll(hostDir, 0755))
	require.NoError(t, os.Chmod(hostDir, 0555))
	t.Cleanup(func() { _ = os.Chmod(hostDir, 0755) })

	collected := &collectedResults{}
	crawlerOptions := newArchiveCrawlerOptions(t, storeDir, collected, nil)
	crawler, err := New(crawlerOptions)
	require.NoError(t, err)
	defer func() { _ = crawler.Close() }()

	err = crawler.Crawl(server.URL)
	require.Error(t, err)
	require.True(t, errors.Is(err, output.ErrStoreResponse), "expected ErrStoreResponse, got %v", err)

	// The failed results were not published as successes.
	require.Empty(t, collected.all())
	require.EqualValues(t, 0, crawlerOptions.OutputWriter.GetResultCount())
	require.Empty(t, archiveFiles(t, storeDir))
}

// TestStoreResponseFilteringIsNotAnError ensures ordinary output filtering
// does not fail the crawl: filtered results are skipped silently and Crawl
// still returns nil.
func TestStoreResponseFilteringIsNotAnError(t *testing.T) {
	server := archiveTestServer(t)
	storeDir := filepath.Join(t.TempDir(), "archive")
	collected := &collectedResults{}

	crawlerOptions := newArchiveCrawlerOptions(t, storeDir, collected, func(opts *types.Options) {
		opts.OutputFilterRegex = []string{".*"} // filter out every result
	})
	crawler, err := New(crawlerOptions)
	require.NoError(t, err)
	defer func() { _ = crawler.Close() }()

	require.NoError(t, crawler.Crawl(server.URL))
	require.Empty(t, collected.all())
	require.EqualValues(t, 0, crawlerOptions.OutputWriter.GetResultCount())
	require.Empty(t, archiveFiles(t, storeDir))
	require.Empty(t, indexLines(t, storeDir))
}
