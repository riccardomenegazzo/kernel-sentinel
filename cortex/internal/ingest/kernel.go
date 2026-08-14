package ingest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/model"
)

// Detections decodes kernel-sentinel newline-delimited JSON detections.
// Unknown fields are deliberately tolerated so the Rust sensor can evolve
// without forcing a lockstep Cortex deployment.
func Detections(r io.Reader) ([]model.Detection, error) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	var out []model.Detection
	line := 0
	for scanner.Scan() {
		line++
		if len(scanner.Bytes()) == 0 {
			continue
		}
		var d model.Detection
		if err := json.Unmarshal(scanner.Bytes(), &d); err != nil {
			return nil, fmt.Errorf("decode detection line %d: %w", line, err)
		}
		out = append(out, d)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read detections: %w", err)
	}
	return out, nil
}
