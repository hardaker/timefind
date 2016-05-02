#!/usr/bin/env python

# used to convert the old monolithic timefind.conf.json into seperate
# single source configurations: source_name.conf.json
#
# takes in via stdin or argument the old configuration and writes out to
# new files in the current directory.
#

import sys
import select
import json
import os.path

if select.select([sys.stdin,],[],[],0.0)[0]:
  data = sys.stdin.read()
elif len(sys.argv) > 1:
  # not checking input
  filename = sys.argv[1]
  with open(filename, 'r') as f:
    data = f.read()
else:
  print "No data input, exiting..."
  sys.exit(0)

if __name__ == "__main__":
  data = json.loads(data)

  # was /tmp/urface, but we'll redefine it to something we want
  indexDir = data['indexDir']
  # XXX set this to what you want
  indexDir = "/home/calvin/timefind/index"

  sources = data['sources']

  for s in sources:
    details      = sources.get(s)

    source_name  = s
    source_type  = details.get('type')
    source_paths = details.get('paths')
    source_inc   = details.get('include')
    source_exc   = details.get('exclude', [])

    result            = dict()
    result['indexDir']= indexDir
    result['type']    = source_type
    result['paths']   = [x.encode('utf-8') for x in source_paths]
    result['include'] = [x.encode('utf-8') for x in source_inc]
    result['exclude'] = [x.encode('utf-8') for x in source_exc]

    result_json = json.dumps(result, indent=1)

    # wanted to double check an entry
    #if "snare" in result['paths'][0]:
    #  print "%s %s" % (s, result)

    #print result['paths'][0]

    #print result_json

    # write *.conf.json to current directory
    conf = source_name + ".conf.json"
    if not os.path.exists(conf):
      print "wrote to %s" % conf
      with open(conf, 'w') as f:
        f.write(result_json)
    else:
      print "%s exists: not writing" % conf
