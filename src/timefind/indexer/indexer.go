package main

import (
	"timefind/index"
	"log"
	"os"
	"runtime"
	"timefind/config"

	"github.com/pborman/getopt"
)

//
// Command-line arguments
//
// TODO should probably put these in a struct?
var configPaths []string = []string{}
var verbose bool = false

func main() {
	getopt.ListVarLong(&configPaths, "config", 'c',
		"REQUIRED: Path to configuration file (can be used multiple times)", "PATH")
	getopt.BoolVarLong(&verbose, "verbose", 'v', "Verbose progress indicators and messages")
	help := getopt.BoolLong("help", 'h', "Show this help message and exit")
	getopt.SetParameters("")
	getopt.Parse()

	if *help {
		getopt.Usage()
		os.Exit(0)
	}

	if len(configPaths) == 0 {
		log.Printf("no configuration (-c/--config) found")
		getopt.Usage()
		os.Exit(1)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// set parallelism (automatic in Go 1.6+)
	if runtime.GOMAXPROCS(0) < runtime.NumCPU() {
		runtime.GOMAXPROCS(runtime.NumCPU())
		log.Printf("setting GOMAXPROCS = NumCPU = %d\n", runtime.NumCPU())
	}

	for _, configPath := range configPaths {

		cfg, err := config.NewConfiguration(configPath)
		if err != nil {
			log.Fatal(err)
			continue
		}

		idx, err := index.NewIndex(cfg)
		if err != nil {
			log.Print(err)
			return
		}

		if err := idx.Update(); err != nil {
			log.Print(err)
			return
		}

		if err := idx.WriteOut(); err != nil {
			log.Print(err)
			return
		}
	}
}

// vim: noet:ts=4:sw=4:tw=80
