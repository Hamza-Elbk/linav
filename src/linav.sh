#!/usr/bin/bash
set -euo pipefail   
shopt -s nullglob
source /etc/linav/linav.conf

SCRIPT_DIR="$(cd ..  && pwd)"
source "$SCRIPT_DIR"/src/utils/logit.sh

# ──────────────────────────────────────────────────────────────
# TODO – Next milestone: create the linav.sh skeleton + CLI parsing
#
# 1. File layout
#    [+] mkdir -p src && touch src/linav.sh
#    [+] declare SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd)"
#    [+] source "$SCRIPT_DIR/utils/logit.sh"
#    [+] source /etc/linav/linav.conf 2>/dev/null || \
#          source "$SCRIPT_DIR/../linav.conf"
#
# 2. usage() helper
#    [ ] Print:  linav.sh -p <path> [-m light|medium|heavy] \
#                      [-j jobs] [--exec fork|thread] [--verbose] [-h]
#
# 3. Parse options
#    [ ] Decide:  getopts (short flags)  *or*  while-case loop for long flags
#    [ ] Mandatory  -p|--path           ➜ TARGET_PATH (absolute via readlink -f)
#    [ ] Optional   -m|--mode           ➜ MODE   (default $DEFAULT_MODE)
#    [ ] Optional   -j|--jobs           ➜ JOBS   (default $JOBS)
#    [ ] Optional   --exec fork|thread  ➜ EXEC_MODE
#    [ ] Optional   --verbose           ➜ VERBOSE=true
#    [ ] -h|--help  ➜ usage + exit 0
#    [ ] On missing path or bad flag     ➜ exit 101 + log ERROR
#
# 4. Global vars after parsing
#    [ ] echo "$MODE / $JOBS / $EXEC_MODE" to verify
#
# 5. Function stubs (only log for now)
#    [ ] collect_targets()     # logit DEBUG "collect_targets() called"
#    [ ] run_scans()
#    [ ] aggregate_results()
#    [ ] cleanup()             # trap cleanup EXIT
#
# 6. Main flow
#    [ ] logit INFO "Linav started (mode=$MODE path=$TARGET_PATH jobs=$JOBS)"
#    [ ] call collect_targets → run_scans → aggregate_results
#    [ ] logit INFO "Linav finished" ; exit 0
#
# 7. Return codes
#    0   success
#    1   internal failure
#    101 bad CLI syntax / missing args
#
# 8. Mini-tests (Bats later)
#    [ ] linav.sh -h            → status 0 & prints “Usage”
#    [ ] linav.sh -m light      → status 101 (no path)
#    [ ] linav.sh -p /tmp       → writes 2×INFO to $LOG_FILE
#
# 9. install.sh update
#    [ ] copy src/linav.sh  →  /usr/local/bin/linav
#    [ ] copy src/utils/*   →  /usr/local/lib/linav/
#    [ ] chmod 755 on the new files
#
# Helpful references for inspiration
# • Timestamped logging patterns in Bash :contentReference[oaicite:0]{index=0}
# • bash getopts + long-option parsing examples :contentReference[oaicite:1]{index=1}
# • CLI skeletons that mix short/long flags :contentReference[oaicite:2]{index=2}
# • Large real-world script with usage()/logger (Linux-Malware-Detect) :contentReference[oaicite:3]{index=3}
#
# End TODO – implement each checkbox when time allows
# ──────────────────────────────────────────────────────────────

# Usage 
usage(){

}


