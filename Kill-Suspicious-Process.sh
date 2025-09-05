#!/bin/bash
set -eu

ScriptName="Kill-Suspicious-Process"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
RunStart="$(date +%s)"

# Prefer ARG1 from Velociraptor, fallback to $1
PID="${ARG1:-${1:-}}"

WriteLog() {
  msg="$1"; lvl="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  line="[$ts][$lvl] $msg"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >> "$LogPath" 2>/dev/null || true
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  size_kb=$(awk -v s="$(wc -c <"$LogPath")" 'BEGIN{printf "%.0f", s/1024}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  i=$((LogKeep-1))
  while [ $i -ge 1 ]; do
    src="$LogPath.$i"; dst="$LogPath.$((i+1))"
    [ -f "$src" ] && mv -f "$src" "$dst" || true
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

escape_json(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
iso_now(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }

BeginNDJSON(){ TMP_AR="$(mktemp)"; }

AddRecord(){
  ts="$(iso_now)"
  pid="$(escape_json "${1:-unknown}")"
  user="$(escape_json "${2:-unknown}")"
  cmd="$(escape_json "${3:-unknown}")"
  exe="$(escape_json "${4:-unknown}")"
  status="$(escape_json "${5:-unknown}")"
  reason="$(escape_json "${6:-}")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"pid":"%s","user":"%s","cmd":"%s","exe":"%s","status":"%s","reason":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$pid" "$user" "$cmd" "$exe" "$status" "$reason" >> "$TMP_AR"
}

AddStatus(){
  ts="$(iso_now)"; st="${1:-info}"; msg="$(escape_json "${2:-}")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"%s","message":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$st" "$msg" >> "$TMP_AR"
}

CommitNDJSON(){
  AR_DIR="$(dirname "$ARLog")"
  [ -d "$AR_DIR" ] || WriteLog "Directory missing: $AR_DIR (will attempt write anyway)" WARN
  if mv -f "$TMP_AR" "$ARLog" 2>/dev/null; then
    :
  else
    WriteLog "Primary write FAILED to $ARLog" WARN
    if mv -f "$TMP_AR" "$ARLog.new" 2>/dev/null; then
      WriteLog "Wrote NDJSON to $ARLog.new (fallback)" WARN
    else
      keep="/tmp/active-responses.$$.ndjson"
      cp -f "$TMP_AR" "$keep" 2>/dev/null || true
      WriteLog "Failed to write both $ARLog and $ARLog.new; saved $keep" ERROR
      rm -f "$TMP_AR" 2>/dev/null || true
      exit 1
    fi
  fi
  for p in "$ARLog" "$ARLog.new"; do
    if [ -f "$p" ]; then
      sz=$(wc -c < "$p" 2>/dev/null || echo 0)
      ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}')
      head1=$(head -n1 "$p" 2>/dev/null || true)
      WriteLog "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}" INFO
    fi
  done
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName (host=$HostName) ==="

# Validate PID argument
if [ -z "${PID:-}" ]; then
  BeginNDJSON; AddStatus "error" "Missing PID argument"; CommitNDJSON; exit 1
fi
case "$PID" in *[!0-9]* ) BeginNDJSON; AddStatus "error" "PID must be numeric: '$PID'"; CommitNDJSON; exit 1 ;; esac

# Safeguards
if [ "$PID" -eq 1 ] || [ "$PID" -eq $$ ] || [ "$PID" -eq "$PPID" ]; then
  BeginNDJSON
  AddRecord "$PID" "" "" "" "skipped" "Refusing to kill critical/self PID"
  CommitNDJSON
  Duration=$(( $(date +%s) - RunStart )); WriteLog "=== SCRIPT END : ${Duration}s ==="
  exit 0
fi

# Gather context (best-effort)
USER_NAME="$(stat -c '%U' "/proc/$PID" 2>/dev/null || echo unknown)"
CMD_RAW="$(tr '\0' ' ' < "/proc/$PID/cmdline" 2>/dev/null || cat "/proc/$PID/comm" 2>/dev/null || echo "")"
CMD="${CMD_RAW% }"
EXE=""; [ -L "/proc/$PID/exe" ] && EXE="$(readlink -f "/proc/$PID/exe" 2>/dev/null || true)"
[ -n "$EXE" ] || EXE="unknown"

if ! kill -0 "$PID" 2>/dev/null; then
  BeginNDJSON
  AddRecord "$PID" "$USER_NAME" "$CMD" "$EXE" "not_found" "Process does not exist"
  CommitNDJSON
  Duration=$(( $(date +%s) - RunStart )); WriteLog "=== SCRIPT END : ${Duration}s ==="
  exit 0
fi

WriteLog "Attempting graceful terminate (TERM) for PID=$PID (exe: $EXE)" INFO
STATUS="failed"; REASON="Unknown failure"

# Try TERM, wait up to 5s
if kill "$PID" 2>/dev/null; then
  for i in 1 2 3 4 5; do
    sleep 1
    if ! kill -0 "$PID" 2>/dev/null; then
      STATUS="killed"; REASON="Terminated with SIGTERM"
      break
    fi
  done
else
  REASON="SIGTERM not sent (permission or other error)"
fi

# If still alive, try KILL
if [ "$STATUS" != "killed" ]; then
  WriteLog "Escalating to SIGKILL (-9) for PID=$PID" WARN
  if kill -9 "$PID" 2>/dev/null; then
    sleep 1
    if ! kill -0 "$PID" 2>/dev/null; then
      STATUS="killed"; REASON="Killed with SIGKILL"
    else
      STATUS="failed"; REASON="SIGKILL sent but process still alive"
    fi
  else
    # Could be no permission or already gone
    if kill -0 "$PID" 2>/dev/null; then
      STATUS="failed"; REASON="Insufficient permissions to kill process"
    else
      STATUS="killed"; REASON="Process exited during attempt"
    fi
  fi
fi

BeginNDJSON
AddRecord "$PID" "$USER_NAME" "$CMD" "$EXE" "$STATUS" "$REASON"
CommitNDJSON

Duration=$(( $(date +%s) - RunStart ))
WriteLog "=== SCRIPT END : ${Duration}s ==="
