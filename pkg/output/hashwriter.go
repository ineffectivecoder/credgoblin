package output

import (
	"fmt"
	"os"
	"sync"
)

// HashWriter writes hashes to a file in a thread-safe manner
type HashWriter struct {
	filePath string
	file     *os.File
	mutex    sync.Mutex
}

// NewHashWriter creates a new hash writer
func NewHashWriter(filePath string) (*HashWriter, error) {
	// Open file in append mode, create if doesn't exist
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open hash file: %w", err)
	}

	return &HashWriter{
		filePath: filePath,
		file:     file,
	}, nil
}

// WriteHash writes a hash to the file
func (w *HashWriter) WriteHash(hash string) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.file == nil {
		return fmt.Errorf("hash writer is closed")
	}

	// Write hash with newline
	_, err := fmt.Fprintf(w.file, "%s\n", hash)
	if err != nil {
		return fmt.Errorf("failed to write hash: %w", err)
	}

	// Flush to ensure data is written
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync hash file: %w", err)
	}

	return nil
}

// Close closes the hash file
func (w *HashWriter) Close() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}

	return nil
}

// FilePath returns the path to the hash file
func (w *HashWriter) FilePath() string {
	return w.filePath
}
