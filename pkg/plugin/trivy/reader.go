package trivy

import (
	"bufio"
	"io"
	"strings"
)

// NewReader removes unnecessary text from the reader that appears before json
func NewReader(rawReader io.ReadCloser) io.ReadCloser {
	return &reader{
		ReadCloser: rawReader,
	}
}

type reader struct {
	io.ReadCloser
	br         *bufio.Reader
	leadingStr strings.Builder
}

func (r *reader) Read(p []byte) (int, error) {
	if r.br == nil {
		r.discardUptoJSON()
	}
	return r.Read(p)
}

// discardUptoJSON discards everything that appears before valid json
func (r *reader) discardUptoJSON() error {
	var b byte
	var leadingStr strings.Builder
	r.br = bufio.NewReaderSize(r.ReadCloser, 2048)
	for {
		nextBytes, err := r.br.Peek(1)
		if err != nil {
			return err
		}
		if string(nextBytes) == "{" {
			break
		}
		b, err = r.br.ReadByte()
		if err != nil {
			return err
		}
		err = leadingStr.WriteByte(b)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *reader) GetLeadingString() string {
	return r.leadingStr.String()
}
