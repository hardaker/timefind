package processor

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	tf_time "timefind/time"

	mrt "github.com/kaorimatz/go-mrt"
	"woozle.org/neale/g.cgi/net/go-pcap.git"
	"xi2.org/x/xz"
)

// An internal counter for debugging purposes
var counter int

// The processor functions are defined in the processors module
type ProcessFunction func(filename string) (tf_time.Times, error)

var Processors map[string]ProcessFunction = map[string]ProcessFunction{
	"bluecoat":        process_bluecoat,
	"bomgar":          process_bomgar,
	"cer":             process_cer,
	"codevision":      process_codevision,
	"cpp":             process_cpp,
	"email":           process_email,
	"fsdb_time_col_1": process_fsdb_time_col_1,
	"fsdb_time_col_2": process_fsdb_time_col_2,
	"iod":             process_iod,
	"juniper":         process_juniper,
	"mrt":             process_mrt,
	"pcap":            process_pcap,
	"sep":             process_sep,
	"snare":           process_snare,
	"stealthwatch":    process_stealthwatch,
	"syslog_rfc3164":  process_syslog_rfc3164,
	"text":            process_text,
	"win_messages":    process_win_messages,
	"wireless":        process_wireless,
}

func process_cpp(filename string) (times tf_time.Times, err error) {
	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		split := strings.Split(line, ",")
		second := split[0]
		day := strings.Split(second, ".")
		when := day[0]
		t, err := strconv.ParseInt(when, 10, 64)
		if err != nil {
			return times, err
		}
		tm := time.Unix(t, 0)
		date := tm.UTC()
		if times.Earliest.IsZero() || date.Before(times.Earliest) {
			times.Earliest = date
		}
		if times.Latest.IsZero() || date.After(times.Latest) {
			times.Latest = date
		}
	}

	return times, nil
}

func process_bomgar(filename string) (times tf_time.Times, err error) {
	var reader io.Reader

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}

	gf, err := gzip.NewReader(f)
	if err != nil {
		f.Seek(0, 0)
		reader = f
	} else {
		reader = gf
		defer gf.Close()
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		r, err := regexp.Compile("when=[0-9]{1,10}")
		if err != nil {
			return times, err
		}
		str := r.FindString(line)
		s := strings.SplitAfter(str, "when=")
		t, err := strconv.ParseInt(s[1], 10, 64)
		if err != nil {
			return times, err
		}
		tm := time.Unix(t, 0)
		date := tm.UTC()
		if times.Earliest.IsZero() || date.Before(times.Earliest) {
			times.Earliest = date
		}
		if times.Latest.IsZero() || date.After(times.Latest) {
			times.Latest = date
		}
	}
	return times, nil
}

func process_bluecoat(filename string) (times tf_time.Times, err error) {
	var reader io.Reader
	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}
	defer f.Close()

	if strings.Contains(filename, ".gz") {
		gf, err := gzip.NewReader(f)
		if err != nil {
			f.Seek(0, 0)
			reader = f
		} else {
			reader = gf
			defer gf.Close()
		}
	} else {
		reader = f
	}

	scanner := bufio.NewScanner(reader)
	for i := 0; i < 6; i++ {
		if scanner.Scan() {
		}
	}
	for scanner.Scan() {
		line := scanner.Text()
		r, err := regexp.Compile("[0-9]{1,4}-[0-9]{1,2}-[0-9]{1,2} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}")
		if err != nil {
			return times, err
		}
		str := r.FindString(line)
		tm, err := time.Parse("2006-01-02 15:04:05", str)
		if err != nil {
			return times, err
		}
		if times.Earliest.IsZero() || tm.Before(times.Earliest) {
			times.Earliest = tm
		}
		if times.Latest.IsZero() || tm.After(times.Latest) {
			times.Latest = tm
		}
	}

	return times, err
}

func process_codevision(filename string) (times tf_time.Times, err error) {
	var reader io.Reader

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}

	gf, err := gzip.NewReader(f)
	if err != nil {
		f.Seek(0, 0)
		reader = f
	} else {
		reader = gf
		defer gf.Close()
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		r, err := regexp.Compile("timestamp=[0-9]{1,4}-[0-9]{1,2}-[0-9]{1,2}T[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}-[0-9]{1,2}:[0-9]{1,2}")
		if err != nil {
			return times, err
		}
		str := r.FindString(line)
		s := strings.SplitAfter(str, "timestamp=")
		t, err := time.Parse("2006-01-02T15:04:05-07:00", s[1])
		tm := t.UTC()
		if err != nil {
			return times, err
		}

		if times.Earliest.IsZero() || tm.Before(times.Earliest) {
			times.Earliest = tm
		}
		if times.Latest.IsZero() || tm.After(times.Latest) {
			times.Latest = tm
		}

	}

	return times, nil
}

func process_cer(filename string) (times tf_time.Times, err error) {
	var reader io.Reader

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}

	gf, err := gzip.NewReader(f)
	if err != nil {
		f.Seek(0, 0)
		reader = f
	} else {
		reader = gf
		defer gf.Close()
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		r, err := regexp.Compile("received=\"[0-9]{1,4}-[0-9]{1,2}-[0-9]{1,2} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}.[0-9]{1,6}-[0-9]{1,2}:[0-9]{1,2}")
		if err != nil {
			return times, nil
		}
		str := r.FindString(line)
		split := strings.SplitAfter(str, "received=\"")
		t, err := time.Parse("2006-01-02 15:04:05.000000-07:00", split[1])
		tm := t.UTC()
		if times.Earliest.IsZero() || tm.Before(times.Earliest) {
			times.Earliest = tm
		}
		if times.Latest.IsZero() || tm.After(times.Latest) {
			times.Latest = tm
		}
	}

	return times, nil
}

func process_sep(filename string) (times tf_time.Times, err error) {
	var reader io.Reader
	var str string
	var s string

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}

	gf, err := gzip.NewReader(f)
	if err != nil {
		f.Seek(0, 0)
		reader = f
	} else {
		reader = gf
		defer gf.Close()
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		r, err := regexp.Compile("Event time: [0-9]{1,4}-[0-9]{1,2}-[0-9]{1,2} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}")
		if err != nil {
			return times, err
		}
		y, err := regexp.Compile("Begin: [0-9]{1,4}-[0-9]{1,2}-[0-9]{1,2} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}")
		if err != nil {
			return times, err
		}
		str = r.FindString(line)
		if str == "" {
			str = y.FindString(line)
			if str == "" {
				x, _ := regexp.Compile("[A-Za-z]{1,3} [0-9]{1,2} [0-9]{1,4} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}")
				date := x.FindString(line)
				if date != "" {
					t, _ := time.Parse("Jan 2 2006 15:04:05", date)
					if times.Earliest.IsZero() || t.Before(times.Earliest) {
						times.Earliest = t
					}
					if times.Latest.IsZero() || t.After(times.Latest) {
						times.Latest = t
					}
				} else {
					s, err := regexp.Compile("[A-Za-z]{1,3} [0-9]{1,2} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}")
					if err != nil {
						return times, err
					}
					str = s.FindString(line)
					split := strings.SplitAfter(filename, ".")
					x, _ := regexp.Compile("[0-9]{1,4}")
					year := x.FindString(split[1])
					join := []string{str, year}
					temp := strings.Join(join, " ")
					t, _ := time.Parse("Jan 2 15:04:05 2006", temp)
					if times.Earliest.IsZero() || t.Before(times.Earliest) {
						times.Earliest = t
					}
					if times.Latest.IsZero() || t.After(times.Latest) {
						times.Latest = t
					}
				}
			} else {
				split := strings.Split(str, "Begin: ")
				s = split[1]
			}
		} else {
			split := strings.Split(str, "Event time: ")
			s = split[1]
		}
		if str != "" {
			t, _ := time.Parse("2006-01-02 15:04:05", s)
			if times.Earliest.IsZero() || t.Before(times.Earliest) {
				times.Earliest = t
			}
			if times.Latest.IsZero() || t.After(times.Latest) {
				times.Latest = t
			}
		}
	}

	return times, nil
}

func process_juniper(filename string) (times tf_time.Times, err error) {
	var reader io.Reader

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}

	gf, err := gzip.NewReader(f)
	if err != nil {
		f.Seek(0, 0)
		reader = f
	} else {
		reader = gf
		defer gf.Close()
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		r, _ := regexp.Compile("[0-9]{1,4}-[0-9]{1,2}-[0-9]{1,2} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}")
		str := r.FindString(line)
		if str != "" {
			t, _ := time.Parse("2006-01-02 15:04:05", str)
			if times.Earliest.IsZero() || t.Before(times.Earliest) {
				times.Earliest = t
			}
			if times.Latest.IsZero() || t.After(times.Latest) {
				times.Latest = t
			}
		} else {
			y, _ := regexp.Compile("[A-Za-z]{1,3} [0-9]{1,2} [0-9]{1,4} [0-9[{1,2}:[0-9]{1,2}:[0-9]{1,2}")
			s := y.FindString(line)
			if s != "" {
				t, _ := time.Parse("Jan 2 2006 15:04:05", s)
				if times.Earliest.IsZero() || t.Before(times.Earliest) {
					times.Earliest = t
				}
				if times.Latest.IsZero() || t.After(times.Latest) {
					times.Latest = t
				}
			} else {
				m, err := regexp.Compile("[A-Za-z]{1,3} [0-9]{1,2} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}")
				if err != nil {
					return times, err
				}
				str = m.FindString(line)
				split := strings.SplitAfter(filename, ".")
				x, _ := regexp.Compile("[0-9]{1,4}")
				year := x.FindString(split[1])
				join := []string{str, year}
				temp := strings.Join(join, " ")
				t, _ := time.Parse("Jan 2 15:04:05 2006", temp)
				if times.Earliest.IsZero() || t.Before(times.Earliest) {
					times.Earliest = t
				}
				if times.Latest.IsZero() || t.After(times.Latest) {
					times.Latest = t
				}
			}
		}
	}
	return times, nil
}

func process_email(filename string) (times tf_time.Times, err error) {

	var reader io.Reader

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}

	gf, err := gzip.NewReader(f)
	if err != nil {
		f.Seek(0, 0)
		reader = f
	} else {
		reader = gf
		defer gf.Close()
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		r, err := regexp.Compile("DATETIME][0-9]{1,4}.[0-9]{1,2}.[0-9]{1,2} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}.[0-9]{1,6}")
		if err != nil {
			return times, err
		}
		str := r.FindString(line)
		if str != "" {
			date := strings.SplitAfter(str, "DATETIME]")
			t, _ := time.Parse("2006.01.02 15:04:05.000000", date[1])
			if times.Earliest.IsZero() || t.Before(times.Earliest) {
				times.Earliest = t
			}
			if times.Latest.IsZero() || t.After(times.Latest) {
				times.Latest = t
			}
		}
	}
	return times, nil
}

func process_text(filename string) (times tf_time.Times, err error) {

	var reader io.Reader

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}

	gf, err := gzip.NewReader(f)
	if err != nil {
		f.Seek(0, 0)
		reader = f
	} else {
		reader = gf
		defer gf.Close()
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		r, err := regexp.Compile("[A-Za-z]{1,3} [0-9]{1,2} [0-9]{1,4} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}")
		if err != nil {
			return times, err
		}
		str := r.FindString(line)
		//log.Printf("%s\n", str)
		if str != "" {
			t, _ := time.Parse("Jan 2 2006 15:04:05", str)
			if times.Earliest.IsZero() || t.Before(times.Earliest) {
				times.Earliest = t
			}
			if times.Latest.IsZero() || t.After(times.Latest) {
				times.Latest = t
			}
		} else {
			s, err := regexp.Compile("[A-Za-z]{1,3} [0-9]{1,2} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}")
			if err != nil {
				return times, err
			}
			str = s.FindString(line)
			split := strings.SplitAfter(filename, ".")
			x, _ := regexp.Compile("[0-9]{1,4}")
			year := x.FindString(split[1])
			join := []string{str, year}
			temp := strings.Join(join, " ")
			t, _ := time.Parse("Jan 2 15:04:05 2006", temp)
			if times.Earliest.IsZero() || t.Before(times.Earliest) {
				times.Earliest = t
			}
			if times.Latest.IsZero() || t.After(times.Latest) {
				times.Latest = t
			}
		}
	}
	return times, nil
}

func process_snare(filename string) (times tf_time.Times, err error) {

	var reader io.Reader

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}

	gf, err := gzip.NewReader(f)
	if err != nil {
		f.Seek(0, 0)
		reader = f
	} else {
		reader = gf
		defer gf.Close()
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		y, _ := regexp.Compile("[A-Za-z]{1,3} [A-Za-z]{1,3} [0-9]{1,2} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2} [0-9]{1,4}")
		s := y.FindString(line)
		if s != "" {
			t, _ := time.Parse("Mon Jan 02 15:04:05 2006", s)
			if times.Earliest.IsZero() || t.Before(times.Earliest) {
				times.Earliest = t
			}
			if times.Latest.IsZero() || t.After(times.Latest) {
				times.Latest = t
			}
		} else {
			r, _ := regexp.Compile("[0-9]{1,4}-[0-9]{1,2}-[0-9]{1,2}T[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}-[0-9]{1,4}")
			str := r.FindString(line)
			if str != "" {
				t, _ := time.Parse("2006-01-02T15:04:05-0700", str)
				tm := t.UTC()
				if times.Earliest.IsZero() || tm.Before(times.Earliest) {
					times.Earliest = tm
				}
				if times.Latest.IsZero() || tm.After(times.Latest) {
					times.Latest = tm
				}
			}
		}
	}
	return times, nil
}

func process_iod(filename string) (times tf_time.Times, err error) {

	var reader io.Reader

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}

	gf, err := gzip.NewReader(f)
	if err != nil {
		f.Seek(0, 0)
		reader = f
	} else {
		reader = gf
		defer gf.Close()
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		r, _ := regexp.Compile("[0-9]{1,4}-[0-9]{1,2}-[0-9]{1,2}T[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}-[0-9]{1,4}")
		str := r.FindString(line)
		if str != "" {
			t, _ := time.Parse("2006-01-02T15:04:05-0700", str)
			tm := t.UTC()
			if times.Earliest.IsZero() || tm.Before(times.Earliest) {
				times.Earliest = tm
			}
			if times.Latest.IsZero() || tm.After(times.Latest) {
				times.Latest = tm
			}
		}
	}
	return times, nil
}

func process_win_messages(filename string) (times tf_time.Times, err error) {

	var reader io.Reader

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}

	gf, err := gzip.NewReader(f)
	if err != nil {
		f.Seek(0, 0)
		reader = f
	} else {
		reader = gf
		defer gf.Close()
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		r, _ := regexp.Compile("[A-Za-z]{1,3} [A-Za-z]{1,3} [0-9]{1,2} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2} [0-9]{1,4}")
		str := r.FindString(line)
		if str != "" {
			t, _ := time.Parse("Mon Jan 2 15:04:05 2006", str)
			if times.Earliest.IsZero() || t.Before(times.Earliest) {
				times.Earliest = t
			}
			if times.Latest.IsZero() || t.After(times.Latest) {
				times.Latest = t
			}
		} else {
			x, _ := regexp.Compile("[0-9]{1,4}-[0-9]{1,2}-[0-9]{1,2}T[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}-[0-9]{1,2}:[0-9]{1,2}")
			s := x.FindString(line)
			t, _ := time.Parse("2006-01-02T15:04:05-07:00", s)
			tm := t.UTC()
			if times.Earliest.IsZero() || tm.Before(times.Earliest) {
				times.Earliest = tm
			}
			if times.Latest.IsZero() || tm.After(times.Latest) {
				times.Latest = tm
			}
		}
	}
	return times, nil
}

func process_wireless(filename string) (times tf_time.Times, err error) {

	var reader io.Reader

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}

	gf, err := gzip.NewReader(f)
	if err != nil {
		f.Seek(0, 0)
		reader = f
	} else {
		reader = gf
		defer gf.Close()
	}

	scanner := bufio.NewScanner(reader)
	j := 1
	for scanner.Scan() {
		line := scanner.Text()
		y, _ := regexp.Compile("Time=[0-9]{1,4}-[0-9]{1,2}-[0-9]{1,2}T[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}")
		s := y.FindString(line)
		if s != "" {
			split := strings.SplitAfter(s, "Time=")
			t, _ := time.Parse("2006-01-02T15:04:05", split[1])
			if times.Earliest.IsZero() || t.Before(times.Earliest) {
				times.Earliest = t
			}
			if times.Latest.IsZero() || t.After(times.Latest) {
				times.Latest = t
			}
		} else {
			r, _ := regexp.Compile("[A-Za-z]{1,3} [0-9]{1,2} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2} [0-9]{1,4}")
			str := r.FindString(line)
			if str != "" {
				t, _ := time.Parse("Jan 2 15:04:05 2006", str)
				if times.Earliest.IsZero() || t.Before(times.Earliest) {
					times.Earliest = t
				}
				if times.Latest.IsZero() || t.After(times.Latest) {
					times.Latest = t
				}
			} else {
				tm, err := regexp.Compile("[A-Za-z]{1,3} *[0-9]{1,2} [0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}")
				if err != nil {
					return times, err
				}
				date := tm.FindString(line)
				split := strings.SplitAfter(filename, ".")
				x, _ := regexp.Compile("[0-9]{1,4}")
				year := x.FindString(split[1])
				if year != "" {
					join := []string{date, year}
					temp := strings.Join(join, " ")
					t, _ := time.Parse("Jan 2 15:04:05 2006", temp)
					if times.Earliest.IsZero() || t.Before(times.Earliest) {
						times.Earliest = t
						log.Println(j, "   ", t)
					}
					if times.Latest.IsZero() || t.After(times.Latest) {
						times.Latest = t
					}
				}
			}
		}
		j += 1
	}
	return times, nil
}

func process_stealthwatch(filename string) (times tf_time.Times, err error) {

	var reader io.Reader

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}

	gf, err := gzip.NewReader(f)
	if err != nil {
		f.Seek(0, 0)
		reader = f
	} else {
		reader = gf
		defer gf.Close()
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		r, _ := regexp.Compile("[0-9]{1,4}-[0-9]{1,2}-[0-9]{1,2}T[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}")
		str := r.FindString(line)
		if str != "" {
			t, _ := time.Parse("2006-01-02T15:04:05", str)
			if times.Earliest.IsZero() || t.Before(times.Earliest) {
				times.Earliest = t
			}
			if times.Latest.IsZero() || t.After(times.Latest) {
				times.Latest = t
			}
		}

	}
	return times, nil
}

func process_pcap(filename string) (times tf_time.Times, err error) {
	var reader io.Reader

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}
	defer f.Close()

	if strings.Contains(filename, ".gz") {
		// handle gzip
		gf, err := gzip.NewReader(f)
		if err != nil {
			f.Seek(0, 0)
			reader = f
		} else {
			reader = gf
			defer gf.Close()
		}
	} else if strings.Contains(filename, ".xz") {
		// handle xz
		xf, err := xz.NewReader(f, 0)
		if err != nil {
			log.Printf("error reading .xz file = %s, skipping...\n", err)
			return times, err
		} else {
			reader = xf
			// XXX xz has no xz.Close()
		}
	} else {
		// just a plain, raw .pcap file
		reader = f
	}

	// start reading pcap
	pf, err := pcap.NewReader(reader)
	if err != nil {
		return times, err
	}

	for {
		ff, _ := pf.ReadFrame()
		if ff == nil {
			break
		}

		when := ff.Time()
		t := when.UTC()
		if times.Earliest.IsZero() || t.Before(times.Earliest) {
			times.Earliest = t
		}
		if times.Latest.IsZero() || t.After(times.Latest) {
			times.Latest = t
		}
	}

	return times, nil
}

// Process an FSDB-formatted file. Currently we manually process the format of
// this file, but in the future we should read the fsdb header and take the
// column containing the timestamp (as specified in the configuration file).
//
// TODO parse generic FSDB files
// XXX assumes tab-delimited files!
/*

  file format (fsdb_time_col_1) as follows:

  #fsdb -F t epoch_time client_ip client_port qid query
  # includes arpa.
  1430438418.154034       10.2.3.4        36347   43595-  0.0.0.0.in-addr.arpa.
  1430438418.158835       10.2.3.5        54108   45531-  0.0.0.0.in-addr.arpa.
  1430438418.161626       10.2.3.6        56029   34082-  0.0.0.0.in-addr.arpa.

  file format (fsdb_time_col_2) as follows:

  #fsdb -F t msgid epoch_time client_ip client_port qid query
  1  1430438418.154034       10.2.3.4        36347   43595-  0.0.0.0.in-addr.arpa.
  2  1430438418.158835       10.2.3.5        54108   45531-  0.0.0.0.in-addr.arpa.
  3  1430438418.161626       10.2.3.6        56029   34082-  0.0.0.0.in-addr.arpa.

*/

func process_fsdb_time_col_1(filename string) (times tf_time.Times, err error) {
	return process_fsdb(filename, 1)
}

func process_fsdb_time_col_2(filename string) (times tf_time.Times, err error) {
	return process_fsdb(filename, 2)
}

func process_fsdb(filename string, col int) (times tf_time.Times, err error) {

	var reader io.Reader

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}
	defer f.Close()

	if strings.Contains(filename, ".gz") {
		// handle gzip
		gf, err := gzip.NewReader(f)
		if err != nil {
			f.Seek(0, 0)
			reader = f
		} else {
			reader = gf
			defer gf.Close()
		}
	} else if strings.Contains(filename, ".xz") {
		// handle xz
		xf, err := xz.NewReader(f, 0)
		if err != nil {
			log.Printf("error reading .xz file = %s, skipping...\n", err)
			return times, err
		} else {
			reader = xf
			// XXX xz has no xz.Close()
		}
	} else {
		// just a plain .fsdb file
		reader = f
	}

	// now process files
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		// read line
		line := scanner.Text()

		if strings.HasPrefix(line, "#") {
			// if a comment or header, continue
			continue
		}

		// only want the column # "col"
		ts := strings.SplitN(line, "\t", col+1)[col-1]

		// convert unixtimestamp into golang time
		// accepts both second and nanosecond precision
		tm, err := tf_time.UnmarshalTime([]byte(ts))
		if err != nil {
			return times, err
		}

		if times.Earliest.IsZero() || tm.Before(times.Earliest) {
			times.Earliest = tm
		}
		if times.Latest.IsZero() || tm.After(times.Latest) {
			times.Latest = tm
		}
	}

	return times, err
}

// http://www.ietf.org/rfc/rfc3164.txt
//
/* 4.1.2 HEADER Part of a syslog Packet

   The TIMESTAMP field is the local time and is in the format of "Mmm dd
   hh:mm:ss" (without the quote marks) where:

     Mmm is the English language abbreviation for the month of the
     year with the first character in uppercase and the other two
     characters in lowercase.  The following are the only acceptable
     values:

     Jan, Feb, Mar, Apr, May, Jun, Jul, Aug, Sep, Oct, Nov, Dec

     dd is the day of the month.  If the day of the month is less
     than 10, then it MUST be represented as a space and then the
     number.  For example, the 7th day of August would be
     represented as "Aug  7", with two spaces between the "g" and
     the "7".

     hh:mm:ss is the local time.  The hour (hh) is represented in a
     24-hour format.  Valid entries are between 00 and 23,
     inclusive.  The minute (mm) and second (ss) entries are between
     00 and 59 inclusive.
*/
func process_syslog_rfc3164(filename string) (times tf_time.Times, err error) {
	// TODO add a parameter to specify year and timezone
	//
	// XXX year := 0000
	// XXX tz := Zulu

	// 012345678901234
	// Mmm dd hh:mm:ss

	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}
	defer f.Close()

	reader, err := OpenFile(f)
	if err != nil {
		log.Printf("error is getting an io.Reader: %s", err)
		return times, err
	}

	// now process files
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		// read line
		line := scanner.Text()
		ts := line[:15]

		// from "time":
		//   Stamp      = "Jan _2 15:04:05"
		t, err := time.Parse(time.Stamp, ts)
		if err != nil {
			return times, err
		}

		if times.Earliest.IsZero() || t.Before(times.Earliest) {
			times.Earliest = t
		}
		if times.Latest.IsZero() || t.After(times.Latest) {
			times.Latest = t
		}
	}
	if err = scanner.Err(); err != nil {
		log.Printf("reading input: ", err)
	}

	return times, err
}

func process_mrt(filename string) (times tf_time.Times, err error) {
	f, err := os.Open(filename)
	if err != nil {
		return times, err
	}
	defer f.Close()

	reader, err := OpenFile(f)
	if err != nil {
		log.Printf("error is getting an io.Reader: %s", err)
		return times, err
	}

	mrtReader := mrt.NewReader(reader)

	// protect ourselves from panic (due to corrupt MRT files)
	defer func() {
		//log.Printf("[mrt] done processing")
		if x := recover(); x != nil {
			log.Printf("[mrt] runtime panic: %v, processing ended early on filename: %s",
				x, filename)
		}
	}()

	for {
		// grab next record
		record, err := mrtReader.Next()

		if record == nil {
			break
		}
		if err != nil {
			log.Printf("[mrt] error: %s, continuing...\n", err)
			continue
		}

		// only care about timestamp
		// TODO check if valid timestamp?
		t := (*record).Timestamp()

		if times.Earliest.IsZero() || t.Before(times.Earliest) {
			times.Earliest = t
		}
		if times.Latest.IsZero() || t.After(times.Latest) {
			times.Latest = t
		}
	}

	// does this return after a panic?
	return times, err
}

func OpenFile(f *os.File) (reader io.Reader, err error) {
	filename := f.Name()
	if strings.HasSuffix(filename, ".gz") {
		// handle gzip
		gf, err := gzip.NewReader(f)
		if err != nil {
			f.Seek(0, 0)
			reader = f
		} else {
			reader = gf
			defer gf.Close()
		}
	} else if strings.HasSuffix(filename, ".bz2") {
		// handle bz2 -- no bzip2.Close() or error return...
		bf := bzip2.NewReader(f)
		reader = bf
	} else if strings.HasSuffix(filename, ".xz") {
		// handle xz
		xf, err := xz.NewReader(f, 0)
		if err != nil {
			log.Printf("error reading .xz file = %s, skipping...\n", err)
			return reader, err
		} else {
			reader = xf
			// XXX xz has no xz.Close()
		}
	} else {
		// just a plain file
		reader = f
	}

	return reader, nil
}
