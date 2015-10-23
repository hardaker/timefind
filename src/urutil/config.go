package urutil

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path"
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
	IndexDir string
	Paths    []string
	Include  []string
	Exclude  []string
	Type     string
	Alias    []string
}

func ReadConfiguration(r io.Reader) (*Configuration, error) {
	decoder := json.NewDecoder(r)
	config := Configuration{}
	err := decoder.Decode(&config)
	if err != nil {
		log.Fatalf("error in decoding config: %s\n", err)
		return nil, err
	}

	// check for shell metacharacters '~'
	for _, paths := range append(config.Paths, config.IndexDir) {
		for _, p := range filepath.SplitList(paths) {
			if strings.HasPrefix(p, "~") {
				err := fmt.Errorf("urutil: paths cannot start with shell metacharacter '~': %q", p)
				return nil, err
			}
		}
	}

	return &config, nil
}

func (cfg *Configuration) NewIndex(section string) (*Index, error) {
	indexFilename := fmt.Sprintf("%s.csv", section)
	indexPathname := path.Join(cfg.IndexDir, indexFilename)
	return NewIndex(indexPathname)
}

func (ds *Configuration) IsMatched(filename string) (bool, error) {
	for _, exc := range ds.Exclude {
		matched, err := filepath.Match(exc, filename)
		if err != nil {
			return false, err
		}
		if matched {
			return false, nil
		}
	}

	for _, inc := range ds.Include {
		matched, err := filepath.Match(inc, filename)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}

	if len(ds.Include) > 0 {
		return false, nil
	} else {
		return true, nil
	}
}

func (ds *Configuration) Walk(results chan<- string) {
	defer close(results)

	walkfunc := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Print(err)
			return nil
		}

		if info.IsDir() {
			// Always descend into subdirs, so no error returned
			return nil
		}

		matched, err := ds.IsMatched(info.Name())
		if err != nil {
			log.Fatal(err)
		}
		if !matched {
			return nil
		}

		results <- path

		return nil
	}

	for _, base := range ds.Paths {
		err := filepath.Walk(base, walkfunc)
		if err != nil {
			log.Print(err)
		}
	}
}
