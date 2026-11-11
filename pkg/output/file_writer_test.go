package output

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFileWriterCloseReportsFlushErrors ensures a flush failure surfaces
// from Close instead of being silently dropped: buffered data that never
// reached the file must not be treated as a successful write.
func TestFileWriterCloseReportsFlushErrors(t *testing.T) {
	fileName := filepath.Join(t.TempDir(), "out.txt")
	writer, err := newFileOutputWriter(fileName)
	require.NoError(t, err)

	require.NoError(t, writer.Write([]byte("buffered-data")))

	// Fault injection: close the underlying file behind the writer's back
	// so the deferred flush fails.
	require.NoError(t, writer.file.Close())

	err = writer.Close()
	require.Error(t, err, "flush error must propagate from Close")
}

// TestFileWriterCloseSuccess ensures Close still returns nil when the flush
// and close both succeed.
func TestFileWriterCloseSuccess(t *testing.T) {
	fileName := filepath.Join(t.TempDir(), "out.txt")
	writer, err := newFileOutputWriter(fileName)
	require.NoError(t, err)
	require.NoError(t, writer.Write([]byte("data")))
	require.NoError(t, writer.Close())

	content, err := os.ReadFile(fileName)
	require.NoError(t, err)
	require.Equal(t, "data\n", string(content))
}

// TestNewFileOutputWriterExclusive ensures exclusive creation fails with
// fs.ErrExist when the file already exists, which the archive namer relies
// on to pick a collision-free name.
func TestNewFileOutputWriterExclusive(t *testing.T) {
	fileName := filepath.Join(t.TempDir(), "out.txt")

	writer, err := newFileOutputWriterExclusive(fileName)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	_, err = newFileOutputWriterExclusive(fileName)
	require.Error(t, err)
	require.True(t, errors.Is(err, fs.ErrExist), "expected fs.ErrExist, got %v", err)
}
