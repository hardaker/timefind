package main

import (
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"timefind/config"
	"timefind/index"
	tf_time "timefind/time"

	"github.com/pborman/getopt"
)

// TODO put in a struct
var configPath []string = []string{}
var verbose bool = false
var beginTimestamp string
var endTimestamp string
var listTimes bool = false
var humanTimes bool = false

var timeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02",
}

func vlog(format string, a ...interface{}) {
	if verbose {
		log.Printf(format, a...)
	}
}

func parseTime(timestr string) (time.Time, error) {
	if len(timestr) == 0 {
		// returns "0001-01-01 00:00:00 +0000 UTC"
		return time.Time{}, nil
	}

	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, timestr); err == nil {
			return t, nil
		}
	}

	// time.Parse doesn't have a Unix timestamp layout
	t := strings.Split(timestr, ".")
	sec, err := strconv.ParseInt(t[0], 10, 64)

	// if we can't parse nanoseconds, it defaults to 0, which is fine
	if err == nil {
		nsec := int64(0)

		if len(t) == 2 {
			nsec, _ = strconv.ParseInt(t[1], 10, 64)
		}

		return time.Unix(sec, nsec), nil
	}

	// exhausted all ways to interpret input timestamps
	err = fmt.Errorf("could not parse timestamp; check format: %q", timestr)
	return time.Time{}, err
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	getopt.ListVarLong(&configPath, "config", 'c',
		"Path to configuration file (can be used multiple times)", "PATH")
	getopt.BoolVarLong(&verbose, "verbose", 'v', "Verbose progress indicators and messages")
	getopt.StringVarLong(&beginTimestamp, "begin", 'b', "Begin interval at timestamp", "TIMESTAMP")
	getopt.StringVarLong(&endTimestamp, "end", 'e', "End interval at timestamp", "TIMESTAMP")
	getopt.BoolVarLong(&listTimes, "times", 't', "Output the start and end time for each path")
	getopt.BoolVarLong(&humanTimes, "human", 'T', "Output human-readable start and end time for each path")
	help := getopt.BoolLong("help", 'h', "Show this help message and exit")

	getopt.SetParameters("SOURCE [SOURCE ...]")
	getopt.Parse()

	getopt.SetUsage(func() {
		getopt.PrintUsage(os.Stderr)
		fmt.Fprintf(os.Stderr,
			`
TIMESTAMP must be in one of the following formats:

 RFC3339Nano	e.g., 2006-01-02T15:04:05.999999999-07:00
 RFC3339	e.g., 2006-01-02T15:04:05-07:00
 YYYY-MM-DD	e.g., 2006-01-02
 Unix time	e.g., 1445471780, 1234471780.372802000

`)
	})

	if *help {
		getopt.Usage()
		os.Exit(0)
	}

	// take a combination of configPaths (filenames)
	// and sources (append .conf.json to get a configPath)
	if len(getopt.Args())+len(configPath) == 0 {
		getopt.Usage()
		os.Exit(1)
	}

	// normalize all non-flag command-line arguments and configPaths.
	// since we're now reading single source configuration files, we
	// specifically take as input one or more .conf.json files.
	//
	// example: timefind dns-data
	//	=> will look for dns-data.conf.json
	//
	// example: timefind -c dns-data.conf.json
	//
	// XXX no support for wildcards
	//
	sources := append(getopt.Args(), configPath...)
	for i, s := range sources {
		if !strings.HasSuffix(s, ".conf.json") {
			sources[i] = fmt.Sprintf("%s%s", s, ".conf.json")
		}
	}
	vlog("looking for configuration files = %+v\n", sources)

	/* TODO handle multiple sections with a delimeter or just list the files?

	option #1 (currently):

		/a/b/c/d.gz
		/a/d/e/f.csv

	option #2:
		dns      /a/b/c/d.gz
		netflow  /a/d/e/f.csv
	*/

	for _, config_path := range sources {

		cfg, err := config.NewConfiguration(config_path)
		if err != nil {
			log.Fatal(err)
		}

		idx, err := index.NewIndex(cfg)
		if err != nil {
			log.Fatal(err)
		}

		earliest, err := parseTime(beginTimestamp)
		if err != nil {
			log.Fatal(err)
		}
		latest, err := parseTime(endTimestamp)
		if err != nil {
			log.Fatal(err)
		}

		// if we have no endTimestamp, set latest to the max time
		if latest == (time.Time{}) {
			vlog("setting endTimestamp to MaxInt32")
			latest = time.Unix(math.MaxInt32, 0)
		}

		vlog("searching for files with timestamp begin: %s, end: %s\n", earliest, latest)

		// Recursively find matching logs in the index within the index tree
		for _, entry := range idx.FindLogs(earliest, latest) {
			if listTimes || humanTimes {
				if humanTimes {
					earliest, _ := (entry.Period.Earliest).MarshalText()
					latest, _ := (entry.Period.Latest).MarshalText()
					fmt.Printf("%s %s %s\n", entry.Path, earliest, latest)
				} else {
					earliest, _ := tf_time.MarshalTime(entry.Period.Earliest)
					latest, _ := tf_time.MarshalTime(entry.Period.Latest)
					fmt.Printf("%s %s %s\n", entry.Path, earliest, latest)
				}
			} else {
				fmt.Println(entry.Path)
			}
		}
	}
}

// vim: noet:ts=4:sw=4:tw=80
