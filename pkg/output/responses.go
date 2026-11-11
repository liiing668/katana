package output

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"
)

// ErrStoreResponse marks failures while archiving a response to disk.
// It is returned (wrapped) by Write when any step of response archival
// (file creation, write, flush, close or index append) fails, so callers
// can tell real I/O errors apart from ordinary output filtering.
var ErrStoreResponse = errors.New("could not store response")

func getResponseHash(URL string) string {
	hash := sha1.Sum([]byte(URL))
	return hex.EncodeToString(hash[:])
}

func (w *StandardWriter) formatResult(result *Result) ([]byte, error) {
	builder := &bytes.Buffer{}

	builder.WriteString(result.Request.URL)
	builder.WriteString("\n\n\n")

	builder.WriteString(result.Request.Raw)

	builder.WriteString("\n\n")

	builder.WriteString(result.Response.Raw)

	return builder.Bytes(), nil
}

func getResponseHost(URL string) (string, error) {
	u, err := urlutil.Parse(URL)
	if err != nil {
		return "", err
	}
	return filepath.Clean(strings.ReplaceAll(u.Host, ":", "_")), nil
}

func createHostDir(storeResponseFolder, domain string) (string, error) {
	dir := filepath.Join(storeResponseFolder, domain)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return "", err
	}
	return dir, nil
}

// archiveResponse archives the raw request/response of a result to its own
// file inside the store-response directory and records the file in the
// index. The stored path is published on the result (and thus to JSON
// output) only after both the file and the index entry have been fully
// written; any failure returns an error wrapping ErrStoreResponse and
// leaves the result unpublished.
func (w *StandardWriter) archiveResponse(result *Result) error {
	data, err := w.formatResult(result)
	if err != nil {
		return fmt.Errorf("output: %w: %v", ErrStoreResponse, err)
	}

	// Name the archive after the final (post-redirect) response URL when
	// available, falling back to the requested URL.
	targetURL := result.Request.URL
	if respReq := result.Response.Resp.Request; respReq != nil && respReq.URL != nil {
		targetURL = respReq.URL.String()
	}
	domain, err := getResponseHost(targetURL)
	if err != nil {
		return fmt.Errorf("output: %w: %v", ErrStoreResponse, err)
	}

	// Serialize the whole archive+index operation so concurrent results
	// can never claim the same file name or interleave index lines.
	w.storeResponseMutex.Lock()
	defer w.storeResponseMutex.Unlock()

	fileName, fileWriter, err := createUniqueResponseFile(w.storeResponseDir, domain, targetURL)
	if err != nil {
		return fmt.Errorf("output: %w: %v", ErrStoreResponse, err)
	}

	if err := fileWriter.Write(data); err != nil {
		_ = fileWriter.Close()
		_ = os.Remove(fileName)
		return fmt.Errorf("output: %w: %v", ErrStoreResponse, err)
	}
	if err := fileWriter.Close(); err != nil {
		_ = os.Remove(fileName)
		return fmt.Errorf("output: %w: %v", ErrStoreResponse, err)
	}
	if err := w.updateIndex(fileName, result); err != nil {
		// The archived file is already committed and stays on disk, but
		// without an index entry the result must not be published.
		return fmt.Errorf("output: %w: %v", ErrStoreResponse, err)
	}

	if absPath, err := filepath.Abs(fileName); err == nil {
		fileName = absPath
	}
	result.Response.StoredResponsePath = fileName
	return nil
}

// createUniqueResponseFile creates a new, previously non-existing response
// file for the given URL. The base name is the URL hash; if that file
// already exists (duplicate URL, different POST body, several entries
// redirecting to the same endpoint, or leftovers from a previous run in a
// custom directory), a numeric suffix is appended until a free name is
// found. Creation is exclusive so concurrent writers never overwrite or
// share a file.
func createUniqueResponseFile(storeResponseFolder, domain, URL string) (string, *fileWriter, error) {
	folder, err := createHostDir(storeResponseFolder, domain)
	if err != nil {
		return "", nil, err
	}
	hash := getResponseHash(URL)
	for seq := 0; ; seq++ {
		name := hash + ".txt"
		if seq > 0 {
			name = fmt.Sprintf("%s-%d.txt", hash, seq)
		}
		fileName := filepath.Join(folder, name)
		output, err := newFileOutputWriterExclusive(fileName)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			return "", nil, err
		}
		return fileName, output, nil
	}
}

// updateIndex appends one line ("<file> <url> (<status>)") for the archived
// file to the index. The caller must hold storeResponseMutex.
func (w *StandardWriter) updateIndex(fileName string, result *Result) error {
	index, err := os.OpenFile(filepath.Join(w.storeResponseDir, indexFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	builder := &bytes.Buffer{}
	builder.WriteString(fileName)
	builder.WriteRune(' ')
	builder.WriteString(result.Request.URL)
	builder.WriteRune(' ')
	builder.WriteString("(" + result.Response.Resp.Status + ")")
	builder.WriteRune('\n')

	if _, writeErr := index.Write(builder.Bytes()); writeErr != nil {
		_ = index.Close()
		return writeErr
	}
	return index.Close()
}
