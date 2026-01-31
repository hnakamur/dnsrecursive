package main

import (
	"context"
	"flag"
	"log"

	"github.com/hnakamur/dnsrecursive/dnsplay"
)

func main() {
	inputFilename := flag.String("i", "query.yaml", "input query filename")
	outputFilename := flag.String("o", "scenario.yaml", "output scenario filename")
	flag.Parse()

	if err := run(*inputFilename, *outputFilename); err != nil {
		log.Fatal(err)
	}
}

func run(inputFilename, outputFilename string) error {
	return (&dnsplay.Recorder{}).RunFile(context.TODO(), inputFilename, outputFilename)
}
