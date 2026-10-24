#!/usr/bin/env bash
# One-shot bootstrap for bugXhunter.
#
#   ./bootstrap.sh                 # build + start server locally
#   ./bootstrap.sh --drop HOST     # also drop the agent to a remote target
#   ./bootstrap.sh --token T       # set the auth token (default: change-me)
#
# The target needs only Python 3 + SSH. No git, no pip, no packages.

set -euo pipefail

TOKEN="${BUGXHUNTER_TOKEN:-change-me}"
HOST="0.0.0.0"
PORT=7080
DROP_TARGET=""
FOREGROUND=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --token)      TOKEN="$2"; shift 2 ;;
    --port)       PORT="$2"; shift 2 ;;
    --host)       HOST="$2"; shift 2 ;;
    --drop)       DROP_TARGET="$2"; shift 2 ;;
    --foreground) FOREGROUND=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# 1. Ensure we are in the repo.
if [[ ! -f bugxhunter/__init__.py ]]; then
  if [[ -d bugxhunter ]]; then
    cd bugxhunter
  else
    echo "bugxhunter package not found; clone the repo first." >&2
    exit 1
  fi
fi

# 2. Install server deps (best effort).
python3 -m pip install --quiet uvicorn starlette aiohttp 2>/dev/null || true

# 3. Drop the agent to a remote target if requested.
if [[ -n "$DROP_TARGET" ]]; then
  echo ">> dropping agent to $DROP_TARGET"
  python3 -m bugxhunter.client drop \
    --host "$DROP_TARGET" \
    --user "${BUGX_USER:-operator}" \
    ${BUGX_KEY:+--key "$BUGX_KEY"} \
    --dest "${BUGX_DEST:-~/xbug}"
fi

# 4. Start the server.
PIDFILE="${BUGXHUNTER_PIDFILE:-/tmp/bugxhunter.pid}"
LOGFILE="${BUGXHUNTER_LOGFILE:-/tmp/bugxhunter.log}"
echo ">> starting bugXhunter server on $HOST:$PORT"
if [[ "$FOREGROUND" == "1" ]]; then
  exec python3 -m bugxhunter.server --host "$HOST" --port "$PORT" --token "$TOKEN"
else
  # Daemonize: detach from the terminal, keep running after logout.
  nohup python3 -m bugxhunter.server --host "$HOST" --port "$PORT" \
      --token "$TOKEN" >"$LOGFILE" 2>&1 &
  echo $! >"$PIDFILE"
  echo "   pid=$!  log=$LOGFILE  pidfile=$PIDFILE"
  echo "   stop with: kill \$(cat $PIDFILE)"
fi
