package trivy

import (
	"bufio"
	"io"
)

// NewReader removes unnecessary fields from the json
func NewReader(br *bufio.Reader) io.Reader {
	return &reader{
		br: br,
		//TODO: Create jsonIterator on  br
	}
}

type reader struct {
	io.Reader
	br *bufio.Reader
}

func (r *reader) Read(p []byte) (int, error) {
	// TODO: Read an element from jsonIterator
	// Marshal it into []bytes and load it into p
	return 0, nil
}
