package output

import (
	"bufio"
	"os"
)

// fileWriter is a concurrent file based output writer.
type fileWriter struct {
	file   *os.File
	writer *bufio.Writer
}

// NewFileOutputWriter creates a new buffered writer for a file
func newFileOutputWriter(file string) (*fileWriter, error) {
	output, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	return &fileWriter{file: output, writer: bufio.NewWriter(output)}, nil
}

// newFileOutputWriterExclusive creates a new buffered writer for a file,
// failing if the file already exists.
func newFileOutputWriterExclusive(file string) (*fileWriter, error) {
	output, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return nil, err
	}
	return &fileWriter{file: output, writer: bufio.NewWriter(output)}, nil
}

// WriteString writes an output to the underlying file
func (w *fileWriter) Write(data []byte) error {
	_, err := w.writer.Write(data)
	if err != nil {
		return err
	}
	_, err = w.writer.WriteRune('\n')
	return err
}

// Close closes the underlying writer flushing everything to disk.
// Flush errors are reported: a failed flush means the data never
// reached the file and must not be treated as a successful write.
func (w *fileWriter) Close() error {
	flushErr := w.writer.Flush()
	//nolint:errcheck // we don't care whether sync failed or succeeded.
	w.file.Sync()
	closeErr := w.file.Close()
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}
