#!/bin/bash
set -eu

ScriptName="Kill-Suspicious-Process"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/active-response/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
RunStart="$(date +%s)"

PID="${1:-}"

# Map Velociraptor arguments (ARG1 -> PID)
[ -n "${ARG1:-}" ] && [ -z "$PID" ] && PID="$ARG1"

WriteLog() {
  msg="$1"; lvl="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  line="[$ts][$lvl] $msg"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >> "$LogPath"
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

escape_json() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

BeginNDJSON() {
  TMP_AR="$(mktemp)"
}

AddRecord() {
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  pid="$(escape_json "$1")"
  exe="$(escape_json "$2")"
  status="$(escape_json "$3")"
  reason="$(escape_json "$4")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"pid":"%s","exe":"%s","status":"%s","reason":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$pid" "$exe" "$status" "$reason" >> "$TMP_AR"
}

CommitNDJSON() {
  if mv -f "$TMP_AR" "$ARLog" 2>/dev/null; then
    :
  else
    mv -f "$TMP_AR" "$ARLog.new" 2>/dev/null || printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"error","message":"atomic move failed"}\n' "$(date '+%Y-%m-%d %H:%M:%S%z')" "$HostName" "$ScriptName" > "$ARLog.new"
  fi
}

RotateLog
WriteLog "START $ScriptName"

# Validate PID
if [ -z "$PID" ]; then
  WriteLog "Missing PID argument" "ERROR"
  BeginNDJSON
  AddRecord "unknown" "unknown" "failed" "Missing PID argument"
  CommitNDJSON
  exit 1
fi

case "$PID" in
  ''|*[!0-9]*) WriteLog "PID must be numeric: '$PID'" "ERROR"
               BeginNDJSON; AddRecord "$PID" "unknown" "failed" "PID not numeric"; CommitNDJSON; exit 1 ;;
esac

ExePath="unknown"
if [ -r "/proc/$PID/exe" ]; then
  ExePath="$(readlink -f "/proc/$PID/exe" 2>/dev/null || echo "unknown")"
fi

WriteLog "Attempting to kill PID=$PID (exe: ${ExePath})" "INFO"

Status="failed"
Reason="Failed to kill process"

if kill -9 "$PID" 2>/dev/null; then
  Status="killed"
  Reason="Process killed successfully with SIGKILL (-9)"
else
  if kill -0 "$PID" 2>/dev/null; then
    Reason="Kill signal failed or insufficient permissions"
  else
    Status="killed"
    Reason="Process not present after kill attempt (may have already exited)"
  fi
fi

BeginNDJSON
AddRecord "$PID" "$ExePath" "$Status" "$Reason"
CommitNDJSON

Duration=$(( $(date +%s) - RunStart ))
WriteLog "END $ScriptName in ${Duration}s"
