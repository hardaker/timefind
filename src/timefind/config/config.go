package config

import (
	"encoding/json"
    "log"
	"os"
	"path/filepath"
	"strings"
)

/*type DataSource struct {
	Paths   []string
	Include []string
	Exclude []string
	Type    string
	Alias   []string
}//*/

type Configuration struct {
    Name     string
	IndexDir string
	Paths    []string
	Include  []string
	Exclude  []string
	Type     string
	Alias    []string
}

func NewConfiguration(path string) (*Configuration, error) {

    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer file.Close()

	config := Configuration{}

    decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, err
	}

    // Save the base name of the config file as this configs name.
    config_parts := strings.Split(path, "/")
    config.Name = strings.Split(config_parts[len(config_parts)-1], ".")[0]

    // Normalized all the involved directories to absolute paths
    config.IndexDir, _ = filepath.Abs(config.IndexDir)
    for i, path := range config.Paths {
        config.Paths[i],_ = filepath.Abs(path)
    }

	return &config, nil
}

// a return value of:
//
// false means that the filename either:
//      matched the exclude pattern
//      did not match the include pattern
//
// true can only mean that the filename:
//      matched the include pattern
//
func (cfg *Configuration) Match(path string) bool {
    for _, exclude_pattern := range cfg.Exclude {
        match, err := filepath.Match(exclude_pattern, path)
        if err != nil {
            log.Printf("Bad exclude pattern: %s", exclude_pattern)
            return false
        }
        if match {
            return false
        }
    }

    for _, include_pattern := range cfg.Include {
        match, err := filepath.Match(include_pattern, path)
        if err != nil {
            log.Printf("Bad include pattern: %s", include_pattern)
            return false
        }
        if match {
            return true
        }
    }
    return false
}
