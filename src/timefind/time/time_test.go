package time

import (
	"bytes"
	"testing"
	"time"
)

func TestMarshalToUnixTime(t *testing.T) {
	unixTime = true

	d, _ := time.Parse(time.RFC3339Nano, "2015-07-14T23:52:57.001325Z")
	dm, _ := MarshalTime(d)

	expectedTime := []byte("1436917977.001325000")

	if bytes.Equal(dm, expectedTime) != true {
		t.Error("Expected 1436917977.001325000, got ", string(dm[:]))
	}
}

func TestUnmarshalFromUnixTime(t *testing.T) {
	unixTime = true
	d := []byte("1436917977.001325000")
	du, err := UnmarshalTime(d)
	if err != nil {
		t.Error("Error unmarshaling text: ", err)
	}

	if du.Unix() != 1436917977 {
		t.Error("Expected 1436917977, got ", du.Unix())
	}

	if du.Nanosecond() != 1325000 {
		t.Error("Expected 1325000, got ", du.Nanosecond())
	}
}

func TestUnmarshalFromUnixTimeWithoutNanosecondPrecision(t *testing.T) {
	unixTime = true
	d := []byte("1436917977")
	du, err := UnmarshalTime(d)
	if err != nil {
		t.Error("Error unmarshaling text: ", err)
	}

	if du.Unix() != 1436917977 {
		t.Error("Expected 1436917977, got ", du.Unix())
	}

	if du.Nanosecond() != 0 {
		t.Error("Expected 0, got ", du.Nanosecond())
	}
}

// Make sure that the output of MarshalText(t) is the same as
// t.MarshalText()
func TestMarshalToTime(t *testing.T) {
	unixTime = false
	d, _ := time.Parse(time.RFC3339Nano, "2015-07-14T23:52:57.001325Z")
	dm, _ := MarshalTime(d)

	expectedTime := "2015-07-14T23:52:57.001325Z"
	expectedTime2, _ := d.MarshalText()

	if string(dm) != expectedTime {
		t.Errorf("Expected %s, got %s\n", expectedTime, string(dm))
	}

	if string(dm) != string(expectedTime2) {
		t.Errorf("Expected %s, got %s\n", string(expectedTime2), string(dm))
	}
}

func TestUnmarshalFromTime(t *testing.T) {
	unixTime = false
	dm := []byte("2015-07-14T23:52:57.001325Z")
	cTime, err := UnmarshalTime(dm)

	if err != nil {
		t.Errorf("Error unmarshalling text: %s\n", err)
	}

	if cTime.Unix() != 1436917977 {
		t.Error("Expected 1436917977, got ", cTime.Unix())
	}

	if cTime.Nanosecond() != 1325000 {
		t.Error("Expected 1325000, got ", cTime.Nanosecond())
	}
}
