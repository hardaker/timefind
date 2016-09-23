package time

import (
    "fmt"
    "time"
    "strconv"
    "strings"
)

var unixTime bool = true

type Times struct {
	Earliest time.Time
	Latest   time.Time
}

func (tm *Times) Union(add_period Times) {
    // Merge this period with the one given. The result will be the a period that starts
    // at the earliest and latest points of the two.
    if tm.Earliest.IsZero() || tm.Earliest.After(add_period.Earliest) {
        tm.Earliest = add_period.Earliest
    }
    if tm.Latest.IsZero() || tm.Latest.Before(add_period.Latest) {
        tm.Latest = add_period.Latest
    }
}

// Converts Time t into a Unix timestamp with nanosecond precision
// in the format of: s.nnnnnnnnn
func MarshalTime(t time.Time) ([]byte, error) {

	if unixTime == true {
		sec := t.Unix()
		nsec := t.Nanosecond()

		return []byte(fmt.Sprintf("%d.%09d", sec, nsec)), nil
	} else {
		return t.MarshalText()
	}
}

func UnmarshalTime(data []byte) (time.Time, error) {
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
