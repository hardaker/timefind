package urutil

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pborman/getopt"
)

var unixTime bool = false

type Times struct {
	Earliest time.Time
	Latest   time.Time
}

// Converts Time t into a Unix timestamp with nanosecond precision
// in the format of: s.nnnnnnnnn
func MarshalText(t time.Time) ([]byte, error) {
	if unixTime == true {
		sec := t.Unix()
		nsec := t.Nanosecond()

		return []byte(fmt.Sprintf("%d.%09d", sec, nsec)), nil
	} else {
		return t.MarshalText()
	}
}

func UnmarshalText(data []byte) (time.Time, error) {
	// example unix time: 1046509689.525204000
	// example time.Time: 2003-03-01T09:08:09.525204Z

	// first try RFC 3339 format
	var t time.Time
	err := t.UnmarshalText(data)

	if err == nil {
		return t, err
	}

	// next try Unix timestamp with and without ns precision
	s := strings.Split(string(data[:]), ".")

	if len(s) > 2 {
		return time.Time{}, fmt.Errorf("not a valid timestamp")
	}

	sec, err := strconv.ParseInt(s[0], 10, 64)
	var nsec int64 = 0

	if len(s) == 2 {
		nsec, err = strconv.ParseInt(s[1], 10, 64)
	}

	return time.Unix(sec, nsec), err
}

func UnixTimeToGoTime(data []byte) (time.Time, error) {
	// assume properly formatted Unix timestamp with nanosecond precision
	s := strings.Split(string(data[:]), ".")

	if len(s) > 2 {
		return time.Time{}, fmt.Errorf("not a valid timestamp = %s", string(data[:]))
	}

	sec, _ := strconv.ParseInt(s[0], 10, 64)
	nsec, _ := strconv.ParseInt(s[1], 10, 64)

	return time.Unix(sec, nsec), nil
}

//
//
//

type Entry struct {
	filename string
	Times
}
type EntrySlice []Entry

func (e EntrySlice) Len() int {
	return len(e)
}

func (e EntrySlice) Less(i, j int) bool {
	return e[i].Earliest.Before(e[j].Earliest)
}

func (e EntrySlice) Swap(i, j int) {
	tmp := e[i]
	e[i] = e[j]
	e[j] = tmp
}

//
//
//

type Index struct {
	filename string
	items    map[string]Times
	vanished map[string]bool
	added    bool
}

func NewIndex(filename string) (*Index, error) {
	idx := &Index{
		filename: filename,
		items:    map[string]Times{},
		vanished: map[string]bool{},
	}

	f, err := os.Open(filename)
	if err != nil {
		return idx, nil
	}
	defer f.Close()

	cr := csv.NewReader(f)
	idx.filename = filename

	for {
		recs, err := cr.Read()
		switch err {
		case nil:
		case io.EOF:
			return idx, nil
		default:
			return nil, err
		}
		if len(recs) != 3 {
			return nil, fmt.Errorf("Bad formatting in index %s", filename)
		}

		fn := recs[0]
		var Earliest, Latest time.Time

		Earliest, err = UnmarshalText([]byte(recs[1]))
		if err != nil {
			return nil, err
		}

		Latest, err = UnmarshalText([]byte(recs[2]))
		if err != nil {
			return nil, err
		}

		idx.items[fn] = Times{Earliest, Latest}
	}

	return idx, nil
}

func (idx *Index) FindLogsByTimeRange(earliest time.Time, latest time.Time) []string {
	ret := make([]string, 0)

	for fn, filetimes := range idx.items {
		switch {
		case filetimes.Latest.Before(earliest):
			continue
		case filetimes.Earliest.After(latest):
			continue
		default:
			ret = append(ret, fn)
		}
	}

	return ret
}

func (idx *Index) FindLogsByTimeRangeWithTimes(earliest time.Time, latest time.Time) []string {
	ret := make([]string, 0)

	for fn, filetimes := range idx.items {
		switch {
		case filetimes.Latest.Before(earliest):
			continue
		case filetimes.Earliest.After(latest):
			continue
		default:
			earliestb, _ := MarshalText(filetimes.Earliest)
			latestb, _ := MarshalText(filetimes.Latest)
			line := fmt.Sprintf("%s\t%s\t%s",
				fn, earliestb, latestb)
			ret = append(ret, line)
		}
	}

	return ret
}

type ProcessFunction func(filename string) (Times, error)

// Count path as present in filesystem.
// If it's new to the index, call the processor so we can add it in.
func (idx *Index) CheckIn(path string, processor ProcessFunction) {
	if _, ok := idx.vanished[path]; ok {
		delete(idx.vanished, path)
	} else {
		times, err := processor(path)
		if err != nil {
			// Bummer. Soldier on and hope this gets fixed next time.
			log.Printf("In file %s: %v", path, err)
			return
		}
		idx.items[path] = times
		idx.added = true
	}
}

func (idx *Index) sorted() EntrySlice {
	ret := make(EntrySlice, 0, len(idx.items))
	for fn, times := range idx.items {
		entry := Entry{fn, times}
		ret = append(ret, entry)
	}

	sort.Sort(ret)
	return ret
}

func (idx *Index) WriteOut() error {
	if (!idx.added) && (len(idx.vanished) == 0) {
		return nil
	}

	tmpfn := fmt.Sprintf("%s.new", idx.filename)

	f, err := os.Create(tmpfn)
	if err != nil {
		return err
	}
	defer f.Close()

	cf := csv.NewWriter(f)

	for _, e := range idx.sorted() {
		if _, ok := idx.vanished[e.filename]; ok {
			delete(idx.vanished, e.filename)
			continue
		}
		Earliestb, _ := MarshalText(e.Earliest)
		Latestb, _ := MarshalText(e.Latest)

		recs := []string{e.filename, string(Earliestb), string(Latestb)}
		err := cf.Write(recs)
		if err != nil {
			return err
		}
	}

	cf.Flush()

	// It's okay to rename while open, on Unix,
	// since the file descriptor doesn't care about the filename
	os.Rename(tmpfn, idx.filename)
	idx.added = false

	return nil
}

func init() {
	getopt.BoolVarLong(&unixTime, "unixtime", 'u', "write Unix time to indexes instead of RFC 3339")
}

// vim: noet:ts=4:sw=4:tw=80
