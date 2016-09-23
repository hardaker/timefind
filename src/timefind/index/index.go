package index

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"timefind/config"
	"timefind/processor"
	tf_time "timefind/time"
)

type Entry struct {
	Path     string
	Period   tf_time.Times
	Modified time.Time
	subIndex *Index
}

type Index struct {
	Filename string                // The name of this index
	Config   *config.Configuration // The configuration data for this index.
	subDir   string                // The sub directory of index files that this index applies to.
	entries  map[string]Entry      // It's slice of entries
	Period   tf_time.Times         // The earliest and latest item within this entire index.
	Modified time.Time             // When this index was last modified.
}

// TODO propagate this option from timefind.go
var verbose bool = false

func vlog(format string, a ...interface{}) {
	if verbose {
		log.Printf(format, a...)
	}
}

// Create a new index from a configuration file. Note that this only reads the
// contents of the index from an existing file. To fully populate it from new or
// updated data files, use the 'update' method
func NewIndex(cfg *config.Configuration) (*Index, error) {

	return subIndex(cfg, "")

}

func subIndex(cfg *config.Configuration,
	subDir string) (*Index, error) {
	// cfg - Configuration file
	// subDir - What subDirectory we're on in our indexing.

	filename := filepath.Join(cfg.IndexDir, subDir, cfg.Name+".csv")

	idx := &Index{
		Filename: filename,
		Config:   cfg,
		subDir:   subDir,
		entries:  map[string]Entry{},
		Period:   tf_time.Times{},
		Modified: time.Time{},
	}

	// Open the index file for reading.
	f, err := os.Open(filename)
	if err != nil {
		return idx, nil
	}
	defer f.Close()

	// Make sure a reasonable processor exists
	if _, ok := processor.Processors[cfg.Type]; ok != true {
		return nil, errors.New("Configuration specified unknown data type.")
	}

	idxStat, err := os.Stat(filename)
	idx.Modified = idxStat.ModTime()

	cr := csv.NewReader(f)
	idx.Filename = filename

	// Read in all the existing entries
	for {
		recs, err := cr.Read()
		switch err {
		case nil:
		case io.EOF:
			return idx, nil
		default:
			return nil, err
		}
		if len(recs) < 3 {
			return nil, fmt.Errorf("Bad formatting in index %s", filename)
		}

		entry := Entry{}
		entry.Path = recs[0]

		if entry.Period.Earliest, err = tf_time.UnmarshalTime([]byte(recs[1])); err != nil {
			return nil, err
		}

		if entry.Period.Latest, err = tf_time.UnmarshalTime([]byte(recs[2])); err != nil {
			return nil, err
		}

		// The old format didn't include modification times
		if len(recs) == 4 {
			if entry.Modified, err = tf_time.UnmarshalTime([]byte(recs[3])); err != nil {
				return nil, err
			}
		}

		if idx.Period.Earliest.IsZero() ||
			entry.Period.Earliest.Before(idx.Period.Earliest) {
			idx.Period.Earliest = entry.Period.Earliest
		}
		if idx.Period.Latest.IsZero() ||
			entry.Period.Latest.After(idx.Period.Latest) {
			idx.Period.Latest = entry.Period.Latest
		}

		// If the file path isn't absolute, this should be a subdirectory.
		if filepath.IsAbs(entry.Path) == false {
			subDir := filepath.Join(idx.subDir, entry.Path)
			subidx_path := filepath.Join(cfg.IndexDir, subDir)

			// Make sure the index subdirectory exists and is a directory.
			info, err := os.Stat(subidx_path)
			if (err == nil || os.IsExist(err)) && info.IsDir() {
				subidx, err := subIndex(cfg, subDir)
				if err != nil {
					log.Print("Could not read index from subdirectory: ", subDir)
				}
				entry.subIndex = subidx
			}
		}

		vlog("idx - ", entry.Period)
		idx.entries[recs[0]] = entry
	}

	return idx, nil
}

// Update all the records for this index and all sub indexes.
func (idx *Index) Update() error {
	for path, _ := range idx.entries {
		_, err := os.Stat(path)
		if err != nil {
			// The path probably doesn't exist, or is otherwise inaccessible.
			// If the path corresponds to a subdir, it won't be a full path
			// though, so try it under each of the cfg paths
			found := false
			for _, base_dir := range idx.Config.Paths {
				dirPath := filepath.Join(base_dir, idx.subDir, path)
				info, err := os.Stat(dirPath)
				if err == nil && info.IsDir() == true {
					found = true
					break
				}
			}
			if found == false {
				log.Print("Removing missing file", path)
				// It wasn't a directory, so it looks like it's missing.
				delete(idx.entries, path)
			}
		}
	}

	// Reset the index's time period
	idx.Period = tf_time.Times{}

	subDirs := make(map[string]bool)

	// We tested to make sure this existed on instantiation
	process, _ := processor.Processors[idx.Config.Type]

	// Process each data directory in our cfgs
	for _, base_dir := range idx.Config.Paths {
		dataPath := filepath.Join(base_dir, idx.subDir)

		paths, err := ioutil.ReadDir(dataPath)
		if err != nil {
			continue
		}

		for _, info := range paths {
			if info.IsDir() {
				// Note the existence of this directory, but don't index it yet.
				subDirs[info.Name()] = true
				continue
			}

			full_path := filepath.Join(dataPath, info.Name())

			// (A) Check if the matching patterns are valid
			// (B) Check if the filename:
			//   (1) matches the include pattern,
			//   (2) does not match the exclude pattern
			if match := idx.Config.Match(info.Name()); match == true {
				entry, ok := idx.entries[full_path]
				if ok == true {
					if info.ModTime().Equal(entry.Modified) ||
						info.ModTime().Before(entry.Modified) {
						// Make sure to include this time in the index period.
						idx.Period.Union(entry.Period)
						continue // This file hasn't been updated since it was last indexed.
					}
				} else {
					// No entry exists
					entry = Entry{}
					entry.Path = full_path
				}

				entry.Modified = info.ModTime()

				log.Print("Processing data file ", full_path)
				period, err := process(full_path)
				if err != nil {
					return err
				}

				entry.Period = period
				idx.Period.Union(period)

				idx.entries[full_path] = entry
			}
		}
	}

	// Now that we've processed all the files in this directory, recursively
	// process all the subdirectories.
	for dir, _ := range subDirs {
		entry, ok := idx.entries[dir]
		if ok == false {
			entry = Entry{Path: dir,
				Period:   tf_time.Times{},
				Modified: time.Time{},
				subIndex: nil}
		}

		log.Print("Processing subdirectory ", filepath.Join(idx.subDir, dir))

		if entry.subIndex == nil {
			var err error
			entry.subIndex, err = subIndex(idx.Config, filepath.Join(idx.subDir, dir))
			if err != nil {
				return err
			}
		}

		err := entry.subIndex.Update()
		if err != nil {
			return err
		}

		entry.Period = entry.subIndex.Period
		idx.Period.Union(entry.Period)
		entry.Modified = entry.subIndex.Modified

		idx.entries[dir] = entry
	}

	idx.Modified = time.Now().UTC()

	return nil
}

func (idx *Index) FindLogs(earliest time.Time, latest time.Time) []Entry {
	entries := []Entry{}

	vlog("Find Earliest: %s Latest: %s", earliest, latest)

	for _, entry := range idx.entries {
		vlog("Trying: %s, %s", entry.Period.Earliest, entry.Period.Latest)
		switch {
		case entry.Period.Latest.Before(earliest):
			continue
		case entry.Period.Earliest.After(latest):
			continue
		}

		vlog("Found %s", filepath.Join(idx.subDir, entry.Path))

		if entry.subIndex != nil {
			// This is a directory that needs to be searched recursively.
			entries = append(entries, entry.subIndex.FindLogs(earliest, latest)...)
		} else {
			// Just a normal file
			entries = append(entries, entry)
		}

	}

	return entries
}

func (idx *Index) WriteOut() error {
	tmpfn := fmt.Sprintf("%s.new", idx.Filename)

	idxPath, _ := filepath.Split(idx.Filename)
	// Create the index directory if it doesn't exist.
	os.MkdirAll(idxPath, 0777)

	outfile, err := os.Create(tmpfn)
	if err != nil {
		return err
	}
	defer outfile.Close()

	csv_file := csv.NewWriter(outfile)

	for path, entry := range idx.entries {
		Earliest_bytes, _ := tf_time.MarshalTime(entry.Period.Earliest)
		Latest_bytes, _ := tf_time.MarshalTime(entry.Period.Latest)
		Modified_bytes, _ := tf_time.MarshalTime(entry.Modified)

		recs := []string{path,
			string(Earliest_bytes),
			string(Latest_bytes),
			string(Modified_bytes)}
		err := csv_file.Write(recs)
		if err != nil {
			return err
		}

		if entry.subIndex != nil {
			if err := entry.subIndex.WriteOut(); err != nil {
				return err
			}
		}

	}

	csv_file.Flush()

	// It's okay to rename while open, on Unix,
	// since the file descriptor doesn't care about the filename
	os.Rename(tmpfn, idx.Filename)

	return nil
}

// vim: noet:ts=4:sw=4:tw=80
