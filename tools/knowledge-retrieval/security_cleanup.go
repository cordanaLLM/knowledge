package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

func closeWithError(primary error, closer io.Closer) error {
	return errors.Join(primary, closer.Close())
}

func decodeEmbeddingResponse(body io.ReadCloser) (embeddingResponse, error) {
	var decoded embeddingResponse
	decodeErr := json.NewDecoder(body).Decode(&decoded)
	if err := closeWithError(decodeErr, body); err != nil {
		return decoded, fmt.Errorf("read or close embedding response: %w", err)
	}
	return decoded, nil
}
