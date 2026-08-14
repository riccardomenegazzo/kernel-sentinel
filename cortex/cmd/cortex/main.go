package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/agent"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/ingest"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/model"
)

func main() {
	var (
		input   = flag.String("detections", "-", "kernel-sentinel JSONL detections file, or - for stdin")
		service = flag.String("service", "unknown-service", "logical service affected by the incident")
		target  = flag.Float64("slo-target", 0.999, "SLO target as a fraction")
		good    = flag.Uint64("good", 0, "good events in the SLO window")
		total   = flag.Uint64("total", 0, "total events in the SLO window")
		window  = flag.String("window", "30d", "SLO accounting window label")
	)
	flag.Parse()

	reader := os.Stdin
	if *input != "-" {
		f, err := os.Open(*input)
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		reader = f
	}

	detections, err := ingest.Detections(reader)
	if err != nil {
		fatal(err)
	}
	if len(detections) == 0 {
		fatal(fmt.Errorf("no detections supplied"))
	}

	decision := agent.Default().Analyze(model.SLOSnapshot{
		Service: *service,
		Target:  *target,
		Good:    *good,
		Total:   *total,
		Window:  *window,
	}, detections)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(decision); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "cortex:", err)
	os.Exit(1)
}
