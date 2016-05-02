package urutil

import (
	"bytes"
	"testing"
)

func TestConfigurationContainsTilde(t *testing.T) {

	testConfig := 
`{
    "indexDir": "~/index/pcap",
    "type": "pcap",
    "paths": ["~/data/pcap"],
    "include": ["*.gz"],
    "exclude": []
}`

	c := bytes.NewBufferString(testConfig)

	_, err := ReadConfiguration(c)
	if err == nil {
		t.Error("Expected an error as paths cannot start with shell metacharacter '~'")
	}
}
