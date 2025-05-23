#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status.
# Treat unset variables as an error when substituting.
# Pipe failures should cause the whole pipe to fail.
set -euo pipefail
# Globs that match nothing expand to a null string, rather than themselves.
shopt -s nullglob # glob vide = liste vide
#check for root permessions
require_root(){
    if [[ "root" != "$(whoami)" ]] ; then
        echo "[-] Root Permission required " >&2
        exit 1
    fi
}
###############################################################################
# 0. Configuration & Utilities Loading
###############################################################################
require_root
source /etc/linav/linav.conf 
_SCRIPT_DIR_REALPATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_SCRIPT_DIR_REALPATH/.." && pwd)"

if [[ -f "$PROJECT_ROOT/src/utils/logit.sh" ]]; then
  source "$PROJECT_ROOT/src/utils/logit.sh"
else 
 echo "ERROR logit no found " >&2
 exit 1
fi

###############################################################################
# 1. Online Help
###############################################################################
usage() {
  cat <<EOF
Usage: linav.sh -p <path> [options]

Mandatory:
  -p, --path <dir|file>   Target file or directory for scanning.

Options:
  -j, --jobs <N>          Number of parallel workers (default: \$JOBS or number of processors, e.g., $(nproc 2>/dev/null || echo 4)).
      --exec <mode>       Execution mode: fork | proc (default: fork).
                          fork: Uses GNU Parallel.
                          proc: Uses xargs for lightweight multiprocessing.
  -h, --help              Display this help message and exit.

Environment Variables:
  VIRUSTOTAL_API_KEY      Your VirusTotal API key (required for VirusTotal scans).
                          Can be set in /etc/linav/linav.conf or as an environment variable.

Required Tools:
  yara, clamscan, curl, jq, gzip, find, flock, sha256sum (or shasum).
  GNU Parallel if using --exec fork.

Examples:
  sudo linav.sh -p /mnt/usb --jobs 8 --exec proc
  linav.sh --path ~/Downloads
EOF
  exit 0
}

###############################################################################
# 2. Configurable Variables (can be overridden by linav.conf)
###############################################################################
YARA_RULES=${YARA_RULES:-/etc/linav/rules.yar}
LOG_FILE=${LOG_FILE:-/var/log/linav/history.log}
#MAX_ARCH_DEPTH=${MAX_ARCH_DEPTH:-2} # Note: Currently not actively used in scan commands.
JOBS=${JOBS:-$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}
EXEC_MODE=${EXEC_MODE:-fork} # fork | proc (proc == xargs multi-proc)
REPORT_DIR=${REPORT_DIR:-/var/log/linav}
VT_REPORT_DIR=${VT_REPORT_DIR:-$REPORT_DIR/vt_reports}
VT_MIN_INTERVAL=${VT_MIN_INTERVAL:-16} # Seconds. (60 / 4 req/min for VT Public API default)

###############################################################################
# 3. Utility Functions
###############################################################################

# get hash of a given file
sha256() {
  local file_to_hash="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$file_to_hash" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$file_to_hash" | awk '{print $1}'
  else
    log ERROR "sha256sum and shasum not found. Cannot calculate SHA-256 hash."
    return 1
  fi
}


#collect files in a given path 
collect_targets() {
  local src_path="$1"
  local tmp_list_file
  local file_count

  # check if the given src path is valid
  if [[ ! -e "$src_path" ]]; then
      log ERROR "Source path does not exist: $src_path"
      return 1
  fi
  # creating a tmp list to store files path there
  tmp_list_file=$(mktemp "/tmp/collect_targets.XXXXXX.lst") || {
    log ERROR "Failed to create temporary file for targets."
    return 1
  }
  
  #check if its a single file 
  if [[ -f "$src_path" ]]; then
    printf "%s\0" "$src_path" > "$tmp_list_file"
    file_count=1
    log INFO "collect_targets: 1 file listed directly: $src_path"
  # if it is a directory
  elif [[ -d "$src_path" ]]; then
    # store every file in tmplist
    find "$src_path" -xdev -type f -print0 > "$tmp_list_file"
    # count files
    file_count=$(tr -cd '\0' < "$tmp_list_file" | wc -c)
    log INFO "collect_targets: $file_count file(s) listed from directory $src_path"
  else
    log ERROR "Source path is not a file or directory: $src_path"
    rm -f "$tmp_list_file"
    return 1
  fi

  log INFO "collect_targets: Temporary file list created at $tmp_list_file ($(wc -c <"$tmp_list_file") bytes)"
  echo "$file_count"
  echo "$tmp_list_file" 


}

# Initialise variable 
init_linav() {
  JQ_OK=$(command -v jq >/dev/null 2>&1 && echo 1 || echo 0)
  YARA_OK=$(command -v yara >/dev/null 2>&1 && [[ -f "$YARA_RULES" ]] && echo 1 || echo 0)
  CLAM_OK=$(command -v clamscan >/dev/null 2>&1 && echo 1 || echo 0)

  if (( ! YARA_OK )); then log WARN "YARA not found or rules file '$YARA_RULES' missing. YARA scans will be skipped."; fi
  if (( ! CLAM_OK )); then log WARN "ClamScan not found. ClamAV scans will be skipped."; fi
  if (( ! JQ_OK )); then log WARN "jq not found. VirusTotal report parsing will be limited."; fi

  mkdir -p "$VT_REPORT_DIR" || { log ERROR "Failed to create VirusTotal report directory: $VT_REPORT_DIR"; exit 1; }
  if [[ -n "$LOG_FILE" && "$LOG_FILE" != "/dev/stderr" && "$LOG_FILE" != "/dev/stdout" ]]; then
    mkdir -p "$(dirname "$LOG_FILE")" || { log ERROR "Failed to create log directory for: $LOG_FILE"; exit 1; }
  fi
}


vt_rate_limit() {
  local lock_file="/tmp/linav.vtlock"
  # open file descriptor 9 to read and write
  exec 9<>"$lock_file"
  # lock it so other processes do not try to override time
  flock --exclusive 9

  local current_time
  local last_request_time
  local time_to_wait
  current_time=$(date +%s)
  last_request_time=$(head -n 1 <&9 2>/dev/null || echo 0)
  # calculate if there is min interval betwenne last request time and new request
  time_to_wait=$(( VT_MIN_INTERVAL - (current_time - last_request_time) ))
  # if its less than minimal wait 
  if (( time_to_wait > 0 )); then
    log INFO "VT Rate Limiter: Sleeping for $time_to_wait seconds."
    sleep "$time_to_wait"
    current_time=$(date +%s)
  fi
  echo "$current_time" >&9
  # release lock
  exec 9>&-
}

###############################################################################
# 4. Scan Modules (YARA, ClamAV, VirusTotal)
###############################################################################
scan_yara() {
  (( YARA_OK )) || return 0
  local file_to_scan="$1"
  local yara_output
  local yara_stderr_output
  local yara_exit_code
  local stderr_temp
  stderr_temp=$(mktemp)
  # Ensure cleanup of temp file for stderr after function complete
  trap 'rm -f "$stderr_temp"' RETURN 

  yara_output=$(yara -r "$YARA_RULES" "$file_to_scan" 2>"$stderr_temp")
  yara_exit_code=$?
  yara_stderr_output=$(cat "$stderr_temp")
 

  if [[ $yara_exit_code -ne 0 ]]; then
    log WARN "YARA  : $file_to_scan → ERROR (Code: $yara_exit_code): $yara_stderr_output"
  # variable not empty
  elif [[ -n "$yara_output" ]]; then
    log INFO "YARA  : $file_to_scan → MATCH: $yara_output"
    # Report all rule names from matches for summary
    while IFS= read -r line; do
      rule_name=$(echo "$line" | awk '{print $1}')
      echo "LINAV_RESULT:::YARA_MATCH:::${file_to_scan}:::${rule_name}"
    done <<< "$yara_output"
  else
    log INFO "YARA  : $file_to_scan → No match"
  fi
}

scan_clamav() {
  (( CLAM_OK )) || return 0
  local file_to_scan="$1"
  local clam_output
  local clam_stderr_output
  local clam_exit_code
  local stderr_temp
  stderr_temp=$(mktemp)
  trap 'rm -f "$stderr_temp"' RETURN

  clam_output=$(clamscan --infected --no-summary -- "$file_to_scan" 2>"$stderr_temp")
  clam_exit_code=$?
  clam_stderr_output=$(cat "$stderr_temp")
  # rm -f "$stderr_temp" # Handled by trap

  if [[ $clam_exit_code -eq 1 ]]; then
    local virus_name="${clam_output#*: }" # Extracts "Virus.Name FOUND"
    log INFO "CLAMAV: $file_to_scan → INFECTED: $virus_name"
    echo "LINAV_RESULT:::CLAMAV_INFECTED:::${file_to_scan}:::$(echo "$virus_name" | awk '{print $1}')" # Report primary virus name
  elif [[ $clam_exit_code -eq 0 ]]; then
    log INFO "CLAMAV: $file_to_scan → Clean"
  else
    log WARN "CLAMAV: $file_to_scan → ERROR (Code: $clam_exit_code): $clam_stderr_output"
    # echo "LINAV_RESULT:::CLAMAV_ERROR:::${file_to_scan}" # Optional
  fi
}

scan_virustotal() {
  local file_path="$1"
  local file_hash="$2"
  local report_file_gz="$VT_REPORT_DIR/${file_hash}.json.gz"
  local temp_json_file
  local http_code
  local curl_failed=0

  if [[ -z "${VIRUSTOTAL_API_KEY:-}" ]]; then
    log WARN "VT    : VIRUSTOTAL_API_KEY is not set. Skipping VirusTotal scan for $file_path ($file_hash)."
    return 0
  fi

  temp_json_file=$(mktemp "/tmp/vt_response.XXXXXX.json")
  trap 'rm -f "$temp_json_file"' RETURN

  if [[ -s "$report_file_gz" ]]; then
    if gzip -dc -- "$report_file_gz" > "$temp_json_file"; then
      log INFO "VT    : $file_path ($file_hash) → Cache hit. Using local report."
    else
      log WARN "VT    : $file_path ($file_hash) → Failed to decompress cached report $report_file_gz. Fetching new."
      > "$temp_json_file"
    fi
  fi

  if [[ ! -s "$temp_json_file" ]]; then
    log INFO "VT    : $file_path ($file_hash) → Cache miss or invalid. Querying API."
    vt_rate_limit

    http_code=$(curl -sS --max-time 60 -w '%{http_code}' \
                     -H "x-apikey: $VIRUSTOTAL_API_KEY" \
                     -o "$temp_json_file" "https://www.virustotal.com/api/v3/files/$file_hash" || curl_failed=1)

    if [[ $curl_failed -eq 1 ]]; then
      log WARN "VT    : $file_path ($file_hash) → curl command failed (network error or timeout)."
      # echo "LINAV_RESULT:::VT_ERROR:::${file_path}:::CurlFail" # Optional
      return 1
    fi

    if [[ "$http_code" -eq 200 ]]; then
      log INFO "VT    : $file_path ($file_hash) → API query successful (HTTP $http_code). Caching report."
      gzip -c "$temp_json_file" > "$report_file_gz"
    elif [[ "$http_code" -eq 404 ]]; then
      log INFO "VT    : $file_path ($file_hash) → Not found on VirusTotal (HTTP $http_code)."
      gzip -c "$temp_json_file" > "$report_file_gz"
    else
      local response_preview
      response_preview=$(head -c 200 "$temp_json_file" | tr -d '\n\r' || echo "Empty response")
      log WARN "VT    : $file_path ($file_hash) → API query failed (HTTP $http_code). Response: $response_preview"
      # echo "LINAV_RESULT:::VT_ERROR:::${file_path}:::HTTP-$http_code" # Optional
      return 1
    fi
  fi

  if (( ! JQ_OK )); then
    log WARN "VT    : $file_path ($file_hash) → jq not available. Skipping detailed VT report parsing."
    return 0
  fi

  if jq -e 'has("error")' "$temp_json_file" >/dev/null 2>&1; then
    local error_code error_message
    error_code=$(jq -r '.error.code // "UnknownCode"' "$temp_json_file")
    error_message=$(jq -r '.error.message // "Unknown error structure"' "$temp_json_file")
    if [[ "$error_code" == "NotFoundError" ]]; then
      log INFO "VT    : $file_path ($file_hash) → Not found on VirusTotal (parsed from report)."
    else
      log WARN "VT    : $file_path ($file_hash) → VirusTotal API Error in report: [$error_code] $error_message"
    fi
    return 0
  fi

  local ratio first_seen last_seen top_threats
  ratio=$(jq -r '((.data.attributes.last_analysis_stats.malicious // 0) as $m | (.data.attributes.last_analysis_stats | to_entries | map(.value) | add // 0) as $t | if $t == 0 and $m == 0 then "0/0" else "\($m)/\($t)" end)' "$temp_json_file")
  first_seen=$(jq -r '(.data.attributes.first_submission_date // null | if . == null then "N/A" else (tonumber | strftime("%F")) end)' "$temp_json_file")
  last_seen=$(jq -r '(.data.attributes.last_analysis_date // null | if . == null then "N/A" else (tonumber | strftime("%F %T")) end)' "$temp_json_file")
  top_threats=$(jq -r '(.data.attributes.last_analysis_results | if . == null then "" else (to_entries | map(select(.value.category=="malicious"))[0:3] | map(.key) | join(",")) end) // "N/A"' "$temp_json_file")

  log INFO "VT    : $file_path ($file_hash) → Ratio=$ratio, FirstSeen=$first_seen, LastSeen=$last_seen, TopThreats=[$top_threats]"

  if [[ "$ratio" != "0/0" && "$ratio" != "N/A" && -n "$ratio" ]]; then
    local num_malicious
    num_malicious=$(echo "$ratio" | cut -d'/' -f1)
    if [[ "$num_malicious" -gt 0 ]]; then
        echo "LINAV_RESULT:::VT_MALICIOUS:::${file_path}:::${ratio}:::${top_threats}"
    fi
  fi
}

###############################################################################
# 5. Main Worker (scans a single file)
###############################################################################
scan_file_heavy() {
  local file_to_scan="$1"

  # This echo goes to the run-specific results file captured by main
  echo "LINAV_RESULT:::PROCESSING_ATTEMPTED:::${file_to_scan}"

  if [[ ! -f "$file_to_scan" ]]; then
    log ERROR "File not found or is not a regular file: \"$file_to_scan\"" # Goes to global log
    echo "LINAV_RESULT:::FILE_ERROR:::${file_to_scan}:::NotFound" # Goes to run-specific results
    return 1
  fi
  if [[ ! -r "$file_to_scan" ]]; then
    log ERROR "File unreadable (permissions?): \"$file_to_scan\""
    echo "LINAV_RESULT:::FILE_ERROR:::${file_to_scan}:::Unreadable"
    return 1
  fi

  log INFO "Processing: \"$file_to_scan\"" # Goes to global log
  local file_hash
  file_hash=$(sha256 "$file_to_scan") || {
    log ERROR "Failed to hash \"$file_to_scan\". Skipping."
    echo "LINAV_RESULT:::FILE_ERROR:::${file_to_scan}:::HashFail"
    return 1
  }

  scan_yara       "$file_to_scan"
  scan_clamav     "$file_to_scan"
  scan_virustotal "$file_to_scan" "$file_hash"
  # These functions will echo their LINAV_RESULT lines to stdout, which is captured.
}

###############################################################################
# 6. Cleanup & Signal Handling
###############################################################################
declare -g TMP_LIST_FILE=""
declare -g RUN_RESULTS_FILE_FOR_CLEANUP=""

cleanup() {
  log INFO "Cleaning up temporary files..."
  if [[ -n "$TMP_LIST_FILE" && -f "$TMP_LIST_FILE" ]]; then
    rm -f "$TMP_LIST_FILE"
    log INFO "Removed temporary file list: $TMP_LIST_FILE"
  fi
  if [[ -n "$RUN_RESULTS_FILE_FOR_CLEANUP" && -f "$RUN_RESULTS_FILE_FOR_CLEANUP" ]]; then
    rm -f "$RUN_RESULTS_FILE_FOR_CLEANUP"
    log INFO "Removed temporary run results file: $RUN_RESULTS_FILE_FOR_CLEANUP"
  fi
  exec 9>&- 2>/dev/null || true
}
trap cleanup EXIT

handle_interrupt() {
  log WARN "Scan interrupted by signal. Exiting."
  exit 130
}
trap handle_interrupt INT TERM

###############################################################################
# 7. Main Loop (CLI parsing, target collection, dispatch)
###############################################################################
main() {
  
  local target_path=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p|--path)    target_path="$2"; shift 2;;
      -j|--jobs)    JOBS="$2"; shift 2;;
      --exec)       EXEC_MODE="$2"; shift 2;;
      -h|--help)    usage;;
      *)            log ERROR "Unknown option: $1"; usage;;
    esac
  done

  if [[ -z "$target_path" ]]; then
    log ERROR "Missing mandatory --path argument."
    usage
  fi

  init_linav

  local collection_output
  local initial_file_count=0
  collection_output="$(collect_targets "$target_path")" || {
      log ERROR "Failed to collect targets from '$target_path'. Exiting."
      # Call report_summary with 0 files and empty results if collection failed.
      local temp_empty_results; temp_empty_results=$(mktemp "/tmp/linav_empty_results.XXXXXX.txt")
      report_summary "0" "$temp_empty_results" "$target_path"
      rm -f "$temp_empty_results"
      exit 1
  }
  initial_file_count=$(echo "$collection_output" | head -n1)
  TMP_LIST_FILE=$(echo "$collection_output" | tail -n1)

  if [[ ! -f "$TMP_LIST_FILE" || initial_file_count -eq 0 ]]; then
      log INFO "No files found to scan in '$target_path' or error in collection."
      local temp_empty_results; temp_empty_results=$(mktemp "/tmp/linav_empty_results.XXXXXX.txt")
      report_summary "$initial_file_count" "$temp_empty_results" "$target_path"
      rm -f "$temp_empty_results"
      exit 0
  fi

  # Assign to global for cleanup trap
  RUN_RESULTS_FILE_FOR_CLEANUP=$(mktemp "/tmp/linav_run_results.XXXXXX.txt")
  log INFO "Current run results will be temporarily stored in: $RUN_RESULTS_FILE_FOR_CLEANUP"
  log INFO "Starting scan. Mode: $EXEC_MODE, Jobs: $JOBS for $initial_file_count files."

  export -f log sha256 vt_rate_limit scan_yara scan_clamav scan_virustotal scan_file_heavy
  export YARA_RULES JQ_OK YARA_OK CLAM_OK VT_REPORT_DIR VT_MIN_INTERVAL MAX_ARCH_DEPTH LOG_FILE
  export VIRUSTOTAL_API_KEY

  if [[ "$EXEC_MODE" == "proc" ]]; then
    log INFO "Dispatching tasks using xargs..."
    # Each instance of scan_file_heavy appends its stdout (LINAV_RESULT lines) to the results file.
    xargs -0 -a "$TMP_LIST_FILE" -P "$JOBS" -I {} bash -c "scan_file_heavy \"{}\" >> \"$RUN_RESULTS_FILE_FOR_CLEANUP\""
  else
    if ! command -v parallel >/dev/null 2>&1; then
        log ERROR "GNU Parallel not found, but --exec mode is 'fork'. Please install parallel or use --exec proc."
        exit 1
    fi
    log INFO "Dispatching tasks using GNU Parallel..."
    # GNU Parallel collects stdout from all jobs and redirects it once to the results file.
    parallel --will-cite --null --jobs "$JOBS" --bar --halt soon,fail=1 \
      scan_file_heavy :::: "$TMP_LIST_FILE" > "$RUN_RESULTS_FILE_FOR_CLEANUP"
  fi

  log INFO "All scan tasks dispatched. Generating summary report."
  report_summary "$initial_file_count" "$RUN_RESULTS_FILE_FOR_CLEANUP" "$target_path"
  log INFO "Linav scan process finished."
}

###############################################################################
# 8. Summary Report
###############################################################################
report_summary() {
local initial_target_count="$1"
local run_results_file="$2"
local cmd_line_path="$3"

local summary_report_file="$REPORT_DIR/linav_summary_$(date '+%Y%m%d_%H%M%S').txt"

mkdir -p "$REPORT_DIR" || { log ERROR "Failed to create directory for summary report: $REPORT_DIR"; return 1; }

local files_processing_attempted_count=0
local yara_matches_count=0
local clamav_infections_count=0
local vt_malicious_reports_count=0
local files_with_errors_count=0

if [[ -f "$run_results_file" && -s "$run_results_file" ]]; then # Check if file exists and is not empty
files_processing_attempted_count=$(grep -c "LINAV_RESULT:::PROCESSING_ATTEMPTED:::" "$run_results_file" || echo 0)
yara_matches_count=$(grep -c "LINAV_RESULT:::YARA_MATCH:::" "$run_results_file" | tr -d '\n' || echo 0)
clamav_infections_count=$(grep -c "LINAV_RESULT:::CLAMAV_INFECTED:::" "$run_results_file" | tr -d '\n' || echo 0)
vt_malicious_reports_count=$(grep -c "LINAV_RESULT:::VT_MALICIOUS:::" "$run_results_file" | tr -d '\n' || echo 0)
files_with_errors_count=$(grep -c "LINAV_RESULT:::FILE_ERROR:::" "$run_results_file" | tr -d '\n' || echo 0)
elif [[ -f "$run_results_file" ]]; then # File exists but is empty
log INFO "Run results file '$run_results_file' is empty. All counts for this run will be 0."
else # File does not exist
log WARN "Run results file '$run_results_file' not found. Summary for this run will be incomplete (all counts 0)."
fi

local general_errors_logged_count=0
if [[ -f "$LOG_FILE" ]]; then
general_errors_logged_count=$(grep -c -E 'WARN|ERROR' "$LOG_FILE" 2>/dev/null || echo 0)
fi

log INFO "Writing summary report to $summary_report_file"
{
echo "==== Linav Scan Summary ===="
echo "Scan Date:                     $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "Command Line Path Scanned:     $cmd_line_path"
echo "--------------------------------------------------"
echo "Files Initially Targeted:        $initial_target_count"
echo "Files Processing Attempted:    $files_processing_attempted_count"
echo "--------------------------------------------------"
echo "YARA Matches This Run:           $yara_matches_count"
echo "ClamAV Infections This Run:      $clamav_infections_count"
echo "VirusTotal Detections This Run:  $vt_malicious_reports_count"
echo "Files With Scan Errors This Run: $files_with_errors_count"
echo "--------------------------------------------------"
echo ""
echo "Detailed Detections & Errors This Run:"
echo ""

echo "YARA Matches ($yara_matches_count):"
if (( ${yara_matches_count:-0} > 0 )) && [[ -f "$run_results_file" ]]; then
    grep "LINAV_RESULT:::YARA_MATCH:::" "$run_results_file" | awk -F":::" '{printf "  - File: %s (Rule: %s)\n", $3, $4}'
else
    echo "  No YARA matches."
fi
echo ""

echo "ClamAV Infections ($clamav_infections_count):"
if (( ${clamav_infections_count:-0} > 0 )) && [[ -f "$run_results_file" ]]; then
    grep "LINAV_RESULT:::CLAMAV_INFECTED:::" "$run_results_file" | awk -F":::" '{printf "  - File: %s (Virus: %s)\n", $3, $4}'
else
    echo "  No ClamAV infections."
fi
echo ""

echo "VirusTotal Detections ($vt_malicious_reports_count):"
if (( ${vt_malicious_reports_count:-0} > 0 )) && [[ -f "$run_results_file" ]]; then
    grep "LINAV_RESULT:::VT_MALICIOUS:::" "$run_results_file" | awk -F":::" '{printf "  - File: %s (Ratio: %s, Top Threats: [%s])\n", $3, $4, $5}'
else
    echo "  No VirusTotal detections."
fi
echo ""

echo "Files With Scan Errors ($files_with_errors_count):"
if (( ${files_with_errors_count:-0} > 0 )) && [[ -f "$run_results_file" ]]; then
    grep "LINAV_RESULT:::FILE_ERROR:::" "$run_results_file" | awk -F":::" '{printf "  - File: %s (Error: %s)\n", $3, $4}'
else
    echo "  No file-specific scan errors recorded for this run."
fi
echo "--------------------------------------------------"
echo "Total Warnings/Errors in Log:  $general_errors_logged_count (from global log: $LOG_FILE)"
echo "--------------------------------------------------"
echo "Global Log File:               $LOG_FILE"
echo "VirusTotal JSON Reports Dir:   $VT_REPORT_DIR"
echo "This Summary Report File:      $summary_report_file"
echo "=================================================="
} > "$summary_report_file"

log INFO "==== Scan Summary (for this run) ===="
log INFO "Path: $cmd_line_path, Initial Targets: $initial_target_count, Attempts: $files_processing_attempted_count, File Errors: $files_with_errors_count"
log INFO "YARA: $yara_matches_count, ClamAV: $clamav_infections_count, VT Detections: $vt_malicious_reports_count"
log INFO "General Log Errors (from $LOG_FILE): $general_errors_logged_count"
log INFO "Summary report written to $summary_report_file"

send_report_email "$summary_report_file"
}

# Function to send the summary report via email to the configured address
send_report_email() {
  local report_file="$1"
  local recipient_mail="${REPORT_EMAIL:-}"
  local subject="[Linav] Scan Summary Report - $(date '+%Y-%m-%d %H:%M:%S')"
  local smtp_server="${SMTP_SERVER:-smtp.gmail.com}"
  local smtp_port="${SMTP_PORT:-465}"
  local smtp_user="${SMTP_USER:-}" # Set in linav.conf or environment
  local smtp_password="${SMTP_PASSWORD:-}" # Set in linav.conf or environment
  local python_mailer="$PROJECT_ROOT/src/utils/send_email.py"

  if [[ -z "$recipient_mail" || -z "$smtp_user" || -z "$smtp_password" ]]; then
    log WARN "REPORT_EMAIL, SMTP_USER, or SMTP_PASSWORD not set. Skipping email of summary report."
    return 0
  fi

  if [[ ! -f "$python_mailer" ]]; then
    log WARN "Python mailer script not found at $python_mailer. Cannot send summary report email."
    return 1
  fi

  python3 "$python_mailer" "$smtp_server" "$smtp_port" "$smtp_user" "$smtp_password" "$recipient_mail" "$subject" "$report_file" && \
    log INFO "Summary report emailed to $recipient_mail using send_email.py." || \
    log WARN "Failed to send summary report to $recipient_mail using send_email.py."
}

###############################################################################
# Entry Point
###############################################################################
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi