#!/usr/bin/env python3
# Resource-bounded decoding process. Not a filesystem/network sandbox.
import resource
resource.setrlimit(resource.RLIMIT_AS,(384*1024*1024,384*1024*1024))
resource.setrlimit(resource.RLIMIT_CPU,(8,8))
resource.setrlimit(resource.RLIMIT_FSIZE,(2*1024*1024,2*1024*1024))
import json,sys
from pathlib import Path
from core import parse_document
if __name__=='__main__':
    data=Path(sys.argv[1]).read_bytes()
    if len(data)>16*1024*1024: raise SystemExit(1)
    result=parse_document(data,sys.argv[2],int(sys.argv[3]),int(sys.argv[4]))
    print(json.dumps(result,ensure_ascii=False))
