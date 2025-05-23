#!/usr/bin/bash
SCRIPT_DIR="$(cd ..  && pwd)"
source "$SCRIPT_DIR"/src/utils/logit.sh
source /etc/linav/linav.conf
collect_targets() {
  local src_path=$1
  [[ -d $src_path ]] || { log ERROR "No such directory: $src_path"; return 1; }

  local tmp_list
  tmp_list=$(mktemp /tmp/collect_targets.XXXXXX.lst) || return 1
  

  find "$src_path" -xdev -type f -print0 > "$tmp_list"
  file_count=$(tr -cd '\0' < "$tmp_list" | wc -c)
  log INFO "collect_targets: $file_count file(s) listed from $src_path"
  log INFO "collect_targets: $(wc -c <"$tmp_list") byte(s) listed from $src_path"

  echo "$tmp_list"
}


# scan_file_heavy() {
#   local file=$1
#   : "${VIRUSTOTAL_API_KEY:?API key missing}"

#   # --- YARA scan ---
#   local yara_result=""
#   if command -v yara >/dev/null 2>&1 && [[ -f "$YARA_RULES" ]]; then
#     yara_result=$(yara -r "$YARA_RULES" "$file" 2>/dev/null)
#     if [[ -n "$yara_result" ]]; then
#       log INFO "YARA: $file → MATCH: $yara_result"
#     else
#       log INFO "YARA: $file → No match"
#     fi
#   else
#     log WARN "YARA not installed or rules not found, skipping YARA scan"
#   fi

#   # --- SHA-256 ---
#   local hash_file; read -r hash_file _ < <(sha256sum -- "$file")

#    # --- CLAMAV scan ---
#   if command -v clamscan >/dev/null 2>&1; then
#     local clamav_result
#     clamav_result=$(clamscan --no-summary --infected "$file" 2>/dev/null)
#     if [[ -n "$clamav_result" ]]; then
#       log INFO "CLAMAV: $file → INFECTED: $clamav_result"
#     else
#       log INFO "CLAMAV: $file → Clean"
#     fi
#   else
#     log WARN "CLAMAV not installed, skipping ClamAV scan"
#   fi
#   # --- VirusTotal API ---
#   local tmp_json http
#   tmp_json=$(mktemp)
#   http=$(curl -sS -w '%{http_code}' \
#           -H "x-apikey: $VIRUSTOTAL_API_KEY" \
#           -o "$tmp_json" \
#           "https://www.virustotal.com/api/v3/files/$hash_file")

#   if [[ $http == 200 ]]; then
#     # 1. Archive the report (compressed)
#     local report_dir=${VT_REPORT_DIR:-"/var/log/linav/reports/"}
#     mkdir -p "$report_dir"
#     gzip -c "$tmp_json" > "$report_dir/${hash_file}.json.gz"

#     # 2. Fields for the log
#     local ratio first_seen last_scan top_engines
#     ratio=$( jq -r '(.data.attributes.last_analysis_stats.malicious) as $m
#                     | (.data.attributes.last_analysis_stats | to_entries | map(.value) | add) as $t
#                     | "\($m)/\($t)"' "$tmp_json" )
#     first_seen=$(jq -r '.data.attributes.first_submission_date | strftime("%F")' "$tmp_json")
#     last_scan=$( jq -r '.data.attributes.last_analysis_date | strftime("%F %T")' "$tmp_json")
#     top_engines=$( jq -r '.data.attributes.last_analysis_results
#                            | to_entries
#                            | map(select(.value.category=="malicious"))[0:3]
#                            | map(.key) | join(",")' "$tmp_json" )

#     # 3. Synthetic log
#     log INFO "VT: $file → ratio=$ratio, first=$first_seen, last=$last_scan, engines=$top_engines"
#   fi

#   rm -f "$tmp_json"
# }
init_linav() {
  JQ_OK=$(command -v jq   >/dev/null 2>&1 && echo 1 || echo 0)
  YARA_OK=$(command -v yara >/dev/null 2>&1 && [[ -f "$YARA_RULES" ]] && echo 1 || echo 0)
  CLAM_OK=$(command -v clamscan >/dev/null 2>&1 && echo 1 || echo 0)

  VT_REPORT_DIR=${VT_REPORT_DIR:-/var/log/linav/reports}
  VT_MIN_INTERVAL=${VT_MIN_INTERVAL:-16}   # 60 s / 4 req.
  mkdir -p "$VT_REPORT_DIR"
}
vt_rate_limit() {
  local lock=/tmp/linav.vtlock
  {
    flock -n 9 || flock 9          # verrou multi-processus
    local now=$(date +%s)
    local last=$(cat "$lock" 2>/dev/null || echo 0)
    local wait=$(( VT_MIN_INTERVAL - (now - last) ))
    (( wait > 0 )) && sleep "$wait"
    echo "$now" > "$lock"
  } 9>"$lock"
}
scan_yara() {                     # $1 = fichier
  (( YARA_OK )) || return 0
  local res
  res=$(yara -r "$YARA_RULES" "$1" 2>/dev/null)
  [[ -n $res ]] \
      && log INFO  "YARA : $1 → MATCH: $res" \
      || log INFO  "YARA : $1 → No match"
}

scan_clamav() {
  (( CLAM_OK )) || return 0
  local res
  res=$(clamscan --no-summary --infected "$1" 2>/dev/null)
  [[ -n $res ]] \
      && log INFO "CLAMAV: $1 → INFECTED: ${res#*: }" \
      || log INFO "CLAMAV: $1 → Clean"
}

scan_virustotal() {               # $1 = fichier, $2 = sha256
  local file=$1 hash=$2 report="$VT_REPORT_DIR/${hash}.json.gz" tmp http

  # -- cache --
  if [[ -s $report ]]; then
    gzip -dc "$report" > "${report%.gz}.tmp"
    tmp="${report%.gz}.tmp"
  else
    vt_rate_limit                          # respect du quota
    tmp=$(mktemp)
    http=$(curl -sS -w '%{http_code}' -H "x-apikey: $VIRUSTOTAL_API_KEY" \
                -o "$tmp" "https://www.virustotal.com/api/v3/files/$hash")
    [[ $http == 200 ]] || { log WARN "VT: $file → HTTP $http"; rm -f "$tmp"; return; }
    gzip -c "$tmp" > "$report"
  fi

  local ratio first last top
  ratio=$( jq -r '(.data.attributes.last_analysis_stats.malicious) as $m
                  | (.data.attributes.last_analysis_stats | to_entries|map(.value)|add) as $t
                  | "\($m)/\($t)"' "$tmp")
  first=$(jq -r '.data.attributes.first_submission_date|strftime("%F")' "$tmp")
  last=$( jq -r '.data.attributes.last_analysis_date |strftime("%F %T")' "$tmp")
  top=$(  jq -r '.data.attributes.last_analysis_results
                 | to_entries
                 | map(select(.value.category=="malicious"))[0:3]
                 | map(.key)|join(",")' "$tmp")
  log INFO "VT   : $file → ratio=$ratio, first=$first, last=$last, top=$top"
  rm -f "$tmp"
}
scan_file_heavy() {
  local file=$1
  [[ -r $file ]] || { log ERROR "Unreadable: $file"; return 1; }

  # -- SHA-256 (unique clé) --
  local sha; read -r sha _ < <(sha256sum -- "$file")

  scan_yara      "$file"
  scan_clamav    "$file"
  scan_virustotal "$file" "$sha"
}





#collect_targets_light /home/stika
scan_file_heavy /home/stika/Mini-projet/Test/test_files/eicar.com