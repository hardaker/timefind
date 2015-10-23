package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"urutil"

	"github.com/pborman/getopt"
	"woozle.org/neale/g.cgi/net/go-pcap.git"
	"xi2.org/x/xz"
)

//
// Command-line arguments
//
// TODO should probably put these in a struct?
var configPaths []string = []string{}
var verbose bool = false

// This is being used as a global counter for printing.
// TODO redo this in a better way.
var i int

func process_cpp(filename string) (times urutil.Times, err error) {
	i += 1
	if i == 10 {
		log.Println(filename)
		i = 0
	}

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

func process_bomgar(filename string) (times urutil.Times, err error) {
	i += 1
	if i == 10 {
		log.Println(filename)
		i = 0
	}

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

func process_bluecoat(filename string) (times urutil.Times, err error) {
	i += 1
	if i == 10 {
		log.Println(filename)
		i = 0
	}

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

func process_codevision(filename string) (times urutil.Times, err error) {
	i += 1
	if i == 10 {
		log.Println(filename)
		i = 0
	}

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

func process_cer(filename string) (times urutil.Times, err error) {
	i += 1
	if i == 10 {
		log.Println(filename)
		i = 0
	}

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

func process_sep(filename string) (times urutil.Times, err error) {
	i += 1
	if i == 10 {
		log.Println(filename)
		i = 0
	}

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

func process_juniper(filename string) (times urutil.Times, err error) {
	i += 1
	if i == 10 {
		log.Println(filename)
		i = 0
	}

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

func process_email(filename string) (times urutil.Times, err error) {
	i += 1
	if i == 10 {
		log.Println(filename)
		i = 0
	}

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

func process_text(filename string) (times urutil.Times, err error) {
	i += 1
	if i == 10 {
		log.Println(filename)
		i = 0
	}

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

func process_snare(filename string) (times urutil.Times, err error) {
	i += 1
	if i == 10 {
		log.Println(filename)
		i = 0
	}

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

func process_iod(filename string) (times urutil.Times, err error) {
	i += 1
	if i == 10 {
		log.Println(filename)
		i = 0
	}

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

func process_win_messages(filename string) (times urutil.Times, err error) {
	i += 1
	if i == 10 {
		log.Println(filename)
		i = 0
	}

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

func process_wireless(filename string) (times urutil.Times, err error) {
	i += 1
	if i == 10 {
		log.Println(filename)
		i = 0
	}

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

func process_stealthwatch(filename string) (times urutil.Times, err error) {
	i += 1
	if i == 10 {
		log.Println(filename)
		i = 0
	}

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

func process_pcap(filename string) (times urutil.Times, err error) {
	i += 1
	// TODO remove this from all processors
	/*if i == 10 {
		log.Println(filename)
		i = 0
	}*/

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

  file format as follows:

  #fsdb -F t epoch_time client_ip client_port qid query
  # includes arpa.
  1430438418.154034       10.2.3.4        36347   43595-  0.0.0.0.in-addr.arpa.
  1430438418.158835       10.2.3.5        54108   45531-  0.0.0.0.in-addr.arpa.
  1430438418.161626       10.2.3.6        56029   34082-  0.0.0.0.in-addr.arpa.

*/
func process_fsdb_dns(filename string) (times urutil.Times, err error) {

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

		// only want the first column
		ts := strings.SplitN(line, "\t", 2)[0]

		// convert unixtimestamp into golang time
		// accepts both second and nanosecond precision
		tm, err := urutil.UnixTimeToGoTime([]byte(ts))
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

	// XXX until Go 1.5, we need to specify number of max processes
	runtime.GOMAXPROCS(runtime.NumCPU())
	log.Printf("setting GOMAXPROCS = NumCPU = %d\n", runtime.NumCPU())

	for _, configPath := range configPaths {

		configf, err := os.Open(configPath)
		if err != nil {
			log.Fatal(err)
		}
		defer configf.Close()

		cfg, err := urutil.ReadConfiguration(configf)
		if err != nil {
			log.Fatal(err)
		}

		i = 0

		sectionName := configPath[
			strings.LastIndex(configPath, "/")+1:
			strings.LastIndex(configPath, ".conf.json")]
		dataSource := cfg

		// start processing
		var processor urutil.ProcessFunction

		indexFilename := fmt.Sprintf("%s.csv", sectionName)
		indexPathname := path.Join(cfg.IndexDir, indexFilename)

		idx, err := urutil.NewIndex(indexPathname)
		if err != nil {
			log.Printf("creating NewIndex: %s\n", err)
			continue
		}

		switch dataSource.Type {
		case "":
			continue
		case "bluecoat":
			processor = process_bluecoat
		case "bomgar":
			processor = process_bomgar
		case "cer":
			processor = process_cer
		case "codevision":
			processor = process_codevision
		case "cpp":
			processor = process_cpp
		case "email":
			processor = process_email
		case "fsdb_dns":
			processor = process_fsdb_dns
		case "iod":
			processor = process_iod
		case "juniper":
			processor = process_juniper
		case "pcap":
			processor = process_pcap
		case "sep":
			processor = process_sep
		case "snare":
			processor = process_snare
		case "stealthwatch":
			processor = process_stealthwatch
		case "text":
			processor = process_text
		case "win_messages":
			processor = process_win_messages
		case "wireless":
			processor = process_wireless
		}

		log.Printf("Moving to section %s", sectionName)

		results := make(chan string, 20)
		go dataSource.Walk(results)

		count := 0
		for filename := range results {
			//if verbose && (count%20 == 0) {
			if verbose {
				log.Printf("Processing file (#%d): %s", count, filename)
			}
			// XXX probably some opportunities to parallelize here
			idx.CheckIn(filename, processor)
			count += 1
		}

		log.Printf("Finished processing %d files (%s/%s).", count, sectionName, dataSource.Type)

		// TODO upon SIGTERM, write out whatever we have
		// TODO this doesn't return an error when writing index to a write-protected
		// directory
		err = idx.WriteOut()
		if err != nil {
			log.Printf("unable to write index file (source: %s): %s\n", sectionName, err)
			continue
		}
		log.Printf("Wrote index (source: %s) to %s\n", sectionName, indexPathname)
	}
}

// vim: noet:ts=4:sw=4:tw=80
