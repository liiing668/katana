package output

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/katana/pkg/navigation"
	"github.com/projectdiscovery/katana/pkg/utils/extensions"
	"github.com/stretchr/testify/require"
)

func TestCreateDirNameNoClobber_EmptyDirectory(t *testing.T) {
	tempDir := t.TempDir()
	emptySubDir := filepath.Join(tempDir, "archive")
	err := os.Mkdir(emptySubDir, 0755)
	require.NoError(t, err)

	// An empty directory should not increment suffix
	resultDir := createDirNameNoClobber(emptySubDir)
	require.Equal(t, emptySubDir, resultDir)

	// After adding a file, it should increment suffix to archive1
	err = os.WriteFile(filepath.Join(emptySubDir, "sample.txt"), []byte("test"), 0644)
	require.NoError(t, err)

	resultDirWithFile := createDirNameNoClobber(emptySubDir)
	require.Equal(t, filepath.Join(tempDir, "archive1"), resultDirWithFile)
}

func TestStoreResponse_PreserveCustomDirectory(t *testing.T) {
	tempDir := t.TempDir()
	customStoreDir := filepath.Join(tempDir, "my_archive")
	err := os.Mkdir(customStoreDir, 0755)
	require.NoError(t, err)

	sentinelFile := filepath.Join(customStoreDir, "sentinel.txt")
	err = os.WriteFile(sentinelFile, []byte("SENTINEL"), 0644)
	require.NoError(t, err)

	indexFile := filepath.Join(customStoreDir, "index.txt")
	err = os.WriteFile(indexFile, []byte("existing_entry\n"), 0644)
	require.NoError(t, err)

	options := Options{
		StoreResponse:    true,
		StoreResponseDir: customStoreDir,
		NoClobber:        false,
	}

	writer, err := New(options)
	require.NoError(t, err)
	require.NotNil(t, writer)

	// Sentinel file must still exist
	require.FileExists(t, sentinelFile)
	content, err := os.ReadFile(sentinelFile)
	require.NoError(t, err)
	require.Equal(t, "SENTINEL", string(content))

	// Index file must not be truncated
	indexContent, err := os.ReadFile(indexFile)
	require.NoError(t, err)
	require.Contains(t, string(indexContent), "existing_entry")
}

// newStoreResponseResult builds a result with a raw request/response pair.
// finalURL may differ from the request URL to simulate redirects; an empty
// finalURL means no redirect happened.
func newStoreResponseResult(t *testing.T, method, requestURL, finalURL, reqBody, respBody string) *Result {
	t.Helper()
	reqURL, err := url.Parse(requestURL)
	require.NoError(t, err)
	effectiveURL := reqURL
	if finalURL != "" {
		effectiveURL, err = url.Parse(finalURL)
		require.NoError(t, err)
	}
	rawRequest := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", method, reqURL.Path, reqURL.Host, reqBody)
	rawResponse := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(respBody), respBody)
	return &Result{
		Request: &navigation.Request{Method: method, URL: requestURL, Raw: rawRequest},
		Response: &navigation.Response{
			Resp: &http.Response{
				Status:     "200 OK",
				StatusCode: http.StatusOK,
				Request:    &http.Request{Method: method, URL: effectiveURL},
			},
			Body: respBody,
			Raw:  rawResponse,
		},
	}
}

func newStoreResponseWriter(t *testing.T, dir string) *StandardWriter {
	t.Helper()
	writer, err := New(Options{StoreResponse: true, StoreResponseDir: dir, ExtensionValidator: extensions.NewValidator(nil, nil, true)})
	require.NoError(t, err)
	sw, ok := writer.(*StandardWriter)
	require.True(t, ok)
	return sw
}

// readIndexLines returns the non-empty lines of the archive index.
func readIndexLines(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, indexFile))
	require.NoError(t, err)
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// TestStoreResponse_ConcurrentSameURLDistinctFiles ensures that concurrent
// results for the same URL (e.g. different POST bodies) each get their own
// archive file and index entry, without overwriting or mixing contents.
func TestStoreResponse_ConcurrentSameURLDistinctFiles(t *testing.T) {
	storeDir := filepath.Join(t.TempDir(), "archive")
	writer := newStoreResponseWriter(t, storeDir)

	const total = 20
	expected := make(map[string]bool, total)
	var wg sync.WaitGroup
	errs := make([]error, total)
	for i := 0; i < total; i++ {
		body := fmt.Sprintf("payload-%02d", i)
		expected[body] = true
		wg.Add(1)
		go func(i int, body string) {
			defer wg.Done()
			result := newStoreResponseResult(t, http.MethodPost, "http://example.com/api", "", "req-"+body, "resp-"+body)
			errs[i] = writer.Write(result)
		}(i, body)
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	require.EqualValues(t, total, writer.GetResultCount())

	// Every result got its own file; no file was overwritten or shared.
	hostDir := filepath.Join(storeDir, "example.com")
	entries, err := os.ReadDir(hostDir)
	require.NoError(t, err)
	require.Len(t, entries, total)

	seen := make(map[string]bool, total)
	for _, entry := range entries {
		content, err := os.ReadFile(filepath.Join(hostDir, entry.Name()))
		require.NoError(t, err)
		parts := strings.Split(string(content), "\n\n")
		respRaw := parts[len(parts)-1]
		// each file must contain exactly one result's response body
		var matched string
		for body := range expected {
			if strings.Contains(respRaw, "resp-"+body) && strings.Contains(string(content), "req-"+body) {
				matched = body
			}
		}
		require.NotEmpty(t, matched, "file %s does not contain a matching request/response pair: %q", entry.Name(), content)
		require.False(t, seen[matched], "response body %s archived more than once", matched)
		seen[matched] = true
	}
	require.Len(t, seen, total)

	// One index line per archived result, each pointing to an existing file.
	lines := readIndexLines(t, storeDir)
	require.Len(t, lines, total)
	for _, line := range lines {
		fields := strings.Fields(line)
		require.Len(t, fields, 4) // "<path> <url> (200 OK)"
		require.Equal(t, "http://example.com/api", fields[1])
		require.True(t, strings.HasSuffix(line, "(200 OK)"))
		require.FileExists(t, fields[0])
	}
}

// TestStoreResponse_RedirectIndexAndJSONPointToResponse ensures that when a
// request is redirected, the archived file, the index entry and the JSON
// stored_response_path all point to the same file holding the final
// response, and that several entries redirecting to the same endpoint do
// not overwrite each other.
func TestStoreResponse_RedirectIndexAndJSONPointToResponse(t *testing.T) {
	storeDir := filepath.Join(t.TempDir(), "archive")
	writer := newStoreResponseWriter(t, storeDir)

	finalURL := "http://example.com/final"
	var storedPaths []string
	for _, entry := range []string{"/entry1", "/entry2", "/entry3"} {
		result := newStoreResponseResult(t, http.MethodGet, "http://example.com"+entry, finalURL, "", "final-body-"+entry)
		require.NoError(t, writer.Write(result))
		require.NotEmpty(t, result.Response.StoredResponsePath)
		storedPaths = append(storedPaths, result.Response.StoredResponsePath)
	}
	require.EqualValues(t, 3, writer.GetResultCount())

	// All three entries redirect to the same endpoint: three distinct files.
	require.ElementsMatch(t, storedPaths, []string{storedPaths[0], storedPaths[1], storedPaths[2]})
	unique := map[string]bool{}
	for _, path := range storedPaths {
		require.False(t, unique[path], "duplicate stored path %s", path)
		unique[path] = true
		require.FileExists(t, path)
	}
	require.Len(t, unique, 3)

	// Index paths must match the JSON published paths and the files on disk.
	lines := readIndexLines(t, storeDir)
	require.Len(t, lines, 3)
	for i, line := range lines {
		fields := strings.Fields(line)
		require.Len(t, fields, 4) // "<path> <url> (200 OK)"
		require.Equal(t, "http://example.com/entry"+fmt.Sprint(i+1), fields[1])
		require.True(t, strings.HasSuffix(line, "(200 OK)"))
		absPath, err := filepath.Abs(fields[0])
		require.NoError(t, err)
		require.True(t, unique[absPath], "index path %s does not match any published stored path", fields[0])
		require.FileExists(t, fields[0])
	}

	// Each archived file keeps the original request and the final response.
	for i, path := range storedPaths {
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Contains(t, string(content), "GET /entry"+fmt.Sprint(i+1)+" HTTP/1.1")
		require.Contains(t, string(content), "final-body-/entry"+fmt.Sprint(i+1))
	}
}

// TestStoreResponse_ArchiveFailureNotPublished ensures that a failure to
// create the archive file prevents the result from being published: no
// stored path, no index entry, no success count.
func TestStoreResponse_ArchiveFailureNotPublished(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission-based fault injection is ineffective")
	}
	storeDir := filepath.Join(t.TempDir(), "archive")
	writer := newStoreResponseWriter(t, storeDir)

	// Fault injection: make the archive directory read-only so host
	// directory / file creation fails during the crawl.
	require.NoError(t, os.Chmod(storeDir, 0555))
	t.Cleanup(func() { _ = os.Chmod(storeDir, 0755) })

	result := newStoreResponseResult(t, http.MethodGet, "http://example.com/a", "", "", "body-a")
	err := writer.Write(result)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrStoreResponse), "expected ErrStoreResponse, got %v", err)

	require.Empty(t, result.Response.StoredResponsePath)
	require.EqualValues(t, 0, writer.GetResultCount())
	lines := readIndexLines(t, storeDir)
	require.Empty(t, lines)
}

// TestStoreResponse_IndexFailureNotPublished ensures that an index append
// failure prevents the result from being published while the already
// committed archive file is preserved.
func TestStoreResponse_IndexFailureNotPublished(t *testing.T) {
	storeDir := filepath.Join(t.TempDir(), "archive")
	writer := newStoreResponseWriter(t, storeDir)

	// Fault injection: replace the index file with a directory so appends fail.
	require.NoError(t, os.Remove(filepath.Join(storeDir, indexFile)))
	require.NoError(t, os.Mkdir(filepath.Join(storeDir, indexFile), 0755))

	result := newStoreResponseResult(t, http.MethodGet, "http://example.com/b", "", "", "body-b")
	err := writer.Write(result)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrStoreResponse), "expected ErrStoreResponse, got %v", err)

	require.Empty(t, result.Response.StoredResponsePath)
	require.EqualValues(t, 0, writer.GetResultCount())

	// The committed archive file stays on disk even though the result was
	// not published.
	hostDir := filepath.Join(storeDir, "example.com")
	entries, err := os.ReadDir(hostDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	content, err := os.ReadFile(filepath.Join(hostDir, entries[0].Name()))
	require.NoError(t, err)
	require.Contains(t, string(content), "body-b")
}

// TestStoreResponse_PreservesOldFilesInCustomDir ensures that files from a
// previous run in a custom directory are never overwritten, even for the
// same URL.
func TestStoreResponse_PreservesOldFilesInCustomDir(t *testing.T) {
	storeDir := filepath.Join(t.TempDir(), "archive")

	first := newStoreResponseWriter(t, storeDir)
	oldResult := newStoreResponseResult(t, http.MethodGet, "http://example.com/page", "", "", "old-body")
	require.NoError(t, first.Write(oldResult))
	oldPath := oldResult.Response.StoredResponsePath
	require.FileExists(t, oldPath)

	// Second run over the same directory and same URL.
	second := newStoreResponseWriter(t, storeDir)
	newResult := newStoreResponseResult(t, http.MethodGet, "http://example.com/page", "", "", "new-body")
	require.NoError(t, second.Write(newResult))
	newPath := newResult.Response.StoredResponsePath

	require.NotEqual(t, oldPath, newPath)
	content, err := os.ReadFile(oldPath)
	require.NoError(t, err)
	require.Contains(t, string(content), "old-body")
	content, err = os.ReadFile(newPath)
	require.NoError(t, err)
	require.Contains(t, string(content), "new-body")

	// Index is additive across runs.
	require.Len(t, readIndexLines(t, storeDir), 2)
}
