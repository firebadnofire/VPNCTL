#!/bin/sh
# Disposable fixture: emulate a compatible older helper without capabilities.
set -eu
if [ "$1" = self-check ]; then exit 1; fi
if [ "$1" = manifest-rpc ]; then
 /usr/local/libexec/vam-server-fixture-real "$@"
 python3 - "$SUDO_UID" "$2" <<'PY'
import json, pathlib, sys
path=pathlib.Path('/var/lib/vpn-appliance-manager/exchange')/sys.argv[1]/'responses'/(sys.argv[2]+'.json')
response=json.loads(path.read_text())
reply=response.get('result',{}).get('Ok',{})
if reply.get('response')=='info':
 reply['value']['capabilities']=[]
 path.write_text(json.dumps(response))
PY
else
 exec /usr/local/libexec/vam-server-fixture-real "$@"
fi
