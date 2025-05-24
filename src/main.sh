#!/bin/bash

# ==============================================================================
# LinAV Suite Main Script
# ==============================================================================
# This script serves as the entry point for the various LinAV analysis modes.
# It handles command-line options and calls the appropriate analysis module.
# Author: Gemini
# Date: 2025-05-24
# ==============================================================================

# --- Configuration and Constants ---
# Get the name and directory of the main script
SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR_MAIN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define the source directory where the analysis modules are located
SRC_DIR="${SCRIPT_DIR_MAIN}"

# --- Default Option Values ---
TARGET_DIR=""
ANALYSIS_MODE="medium"
FORK_MODE=false                # Option -f: run in background
MULTITHREAD_SIMULATION=false   # Option -t: conceptual, affects heavy mode or -f
SUBSHELL_MODE=false            # Option -s: explicit subshell execution
LOG_DIR_MAIN=""                # Option -l <dir>: directory for logging for this script
RESET_PARAMS=false             # Option -r: reset parameters (admin)

# --- Logging (Logger) ---
# Try to source logit.sh for consistent logging.
# logit.sh is expected in ${SRC_DIR}/utils/logit.sh
if [[ -f "${SRC_DIR}/utils/logit.sh" ]]; then
    # shellcheck disable=SC1091
    source "${SRC_DIR}/utils/logit.sh"
    LOG_LEVEL=${LOG_LEVEL:-INFO} # Default LOG_LEVEL for logit.sh if not set elsewhere
else
    # Fallback logger if logit.sh is not found
    log() {
        local level="$1"
        local message="$2"
        local timestamp
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        if [[ -n "$LOG_DIR_MAIN" && -d "$LOG_DIR_MAIN" && -w "$LOG_DIR_MAIN" ]]; then
            echo "[$timestamp] : $SCRIPT_NAME : $level : $message" >> "$LOG_DIR_MAIN/main_linav_suite.log"
        else
            if [[ "$level" == "ERROR" || "$level" == "WARN" ]]; then
                echo "[$timestamp] : $SCRIPT_NAME : $level : $message" >&2
            else
                echo "[$timestamp] : $SCRIPT_NAME : $level : $message"
            fi
        fi
    }
    log "WARN" "Logging script '${SRC_DIR}/utils/logit.sh' not found. Using fallback logger."
fi

# --- Help Function (Usage) ---
usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] <target_folder>"
    echo ""
    echo "Description:"
    echo "  This script is the main launcher for the LinAV analysis suite."
    echo "  It allows you to choose an analysis mode (light, medium, heavy) and configure"
    echo "  various execution parameters."
    echo ""
    echo "Options:"
    echo "  -h, --help                     Show this help and exit"
    echo "  -p, --path <dir>               Specify the target folder (or file) to scan (required)"
    echo "  -m, --mode light|medium|heavy  Choose the analysis level (default: medium)"
    echo "  -f                             Run the chosen analysis in a background subprocess (fork)"
    echo "  -t                             Simulate multithreaded execution. For 'heavy' mode,"
    echo "                                 this may enable its parallel execution mode."
    echo "  -s                             Explicitly run the analysis in a subshell"
    echo "  -l <dir>                       Enable detailed logging for this main script in the"
    echo "                                 specified directory (<dir>/main_linav_suite.log). May also influence"
    echo "                                 logging of sub-scripts via the MAIN_LOG_DIR environment variable."
    echo "  -r                             Reset LinAV suite parameters (reserved for administrator)"
    echo ""
    echo "Examples:"
    echo "  ./$SCRIPT_NAME -p /home/user/documents_to_scan -m light"
    echo "  ./$SCRIPT_NAME /var/www -m heavy -l /var/log/linav_runs -f"
    echo "  sudo ./$SCRIPT_NAME -r -l /var/log/linav_admin"
    exit 0
}

# --- Command-Line Option Parsing ---
if [[ $# -eq 0 ]]; then
    usage
fi

# Temporary variables for getopts
_TARGET_DIR_OPT=""
_ANALYSIS_MODE_OPT="medium"
_FORK_MODE_OPT=false
_MULTITHREAD_SIMULATION_OPT=false
_SUBSHELL_MODE_OPT=false
_LOG_DIR_MAIN_OPT=""
_RESET_PARAMS_OPT=false

while getopts ":hp:m:ftsl:r" opt; do
  case ${opt} in
    h )
      usage
      ;;
    p )
      _TARGET_DIR_OPT="$OPTARG"
      ;;
    m )
      _ANALYSIS_MODE_OPT="$OPTARG"
      if [[ ! "$_ANALYSIS_MODE_OPT" =~ ^(light|medium|heavy)$ ]]; then
        log "ERROR" "Invalid analysis mode '$_ANALYSIS_MODE_OPT'. Accepted values: light, medium, heavy."
        usage
      fi
      ;;
    f )
      _FORK_MODE_OPT=true
      ;;
    t )
      _MULTITHREAD_SIMULATION_OPT=true
      ;;
    s )
      _SUBSHELL_MODE_OPT=true
      ;;
    l )
      _LOG_DIR_MAIN_OPT="$OPTARG"
      ;;
    r )
      _RESET_PARAMS_OPT=true
      ;;
    \? )
      log "ERROR" "Invalid option: -$OPTARG"
      usage
      ;;
    : )
      log "ERROR" "Option -$OPTARG requires an argument."
      usage
      ;;
  esac
done
shift $((OPTIND -1))

# Assign parsed values (or keep defaults if not changed)
TARGET_DIR="${_TARGET_DIR_OPT}"
ANALYSIS_MODE="${_ANALYSIS_MODE_OPT}"
FORK_MODE=${_FORK_MODE_OPT}
MULTITHREAD_SIMULATION=${_MULTITHREAD_SIMULATION_OPT}
SUBSHELL_MODE=${_SUBSHELL_MODE_OPT}
LOG_DIR_MAIN="${_LOG_DIR_MAIN_OPT}"
RESET_PARAMS=${_RESET_PARAMS_OPT}

# The last non-option argument is considered the target folder if -p was not used
if [[ -z "$TARGET_DIR" && -n "$1" ]]; then
  TARGET_DIR="$1"
  shift
elif [[ -z "$TARGET_DIR" && -z "$1" && "${RESET_PARAMS}" = false ]]; then
  log "ERROR" "Target folder is required. Use -p <dir> or specify it as the last argument."
  usage
fi

if [[ -n "$1" ]]; then
    log "ERROR" "Unrecognized arguments: '$*' after parsing options and target folder."
    usage
fi

# --- Main Script Logic ---

# Initialize logging if -l is specified for this main script
if [[ -n "$LOG_DIR_MAIN" ]]; then
    mkdir -p "$LOG_DIR_MAIN"
    if [[ ! -d "$LOG_DIR_MAIN" || ! -w "$LOG_DIR_MAIN" ]]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] : $SCRIPT_NAME : ERROR : Cannot create or write to log directory: '$LOG_DIR_MAIN'. File logging disabled for this script." >&2
        LOG_DIR_MAIN=""
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] : $SCRIPT_NAME : INFO : Main logging enabled in: '$LOG_DIR_MAIN/main_linav_suite.log'"
        export MAIN_LOG_DIR="$LOG_DIR_MAIN"
    fi
fi

log "INFO" "Script $SCRIPT_NAME started."
log "INFO" "Target Folder: '${TARGET_DIR:-N/A}'"
log "INFO" "Analysis Mode: '$ANALYSIS_MODE'"
log "INFO" "Fork Mode (-f): $FORK_MODE"
log "INFO" "Multithread Simulation (-t): $MULTITHREAD_SIMULATION"
log "INFO" "Explicit Subshell Mode (-s): $SUBSHELL_MODE"
log "INFO" "Main Log Directory (-l): '${LOG_DIR_MAIN:-N/A}'"
log "INFO" "Reset Parameters (-r): $RESET_PARAMS"

# Handle -r option (Reset parameters)
if ${RESET_PARAMS}; then
    if [[ "$(id -u)" -ne 0 ]]; then
        log "ERROR" "The -r option is reserved for the administrator (root)."
        exit 1
    fi
    log "INFO" "Starting parameter reset (admin action)..."
    echo "Resetting parameters (admin action)..."
    # TODO: Implement specific reset logic here. Examples:
    # log "INFO" "Cleaning temporary configurations..."
    # rm -rf /etc/linav/temp_config/*
    # log "INFO" "Deleting old reports older than 30 days..."
    # find "${MAIN_LOG_DIR:-/var/log/linav}" -type f -name "report_*.txt" -mtime +30 -exec rm {} \;
    # log "INFO" "Resetting signature databases (if applicable)..."
    # /opt/linav/bin/update_signatures --force_reset
    log "WARN" "The parameter reset logic (-r) is a placeholder and must be implemented."
    echo "Reset logic to be implemented here."
    log "INFO" "Parameter reset completed (placeholder)."
fi

if [[ -z "$TARGET_DIR" && "${RESET_PARAMS}" = true ]]; then
    log "INFO" "Reset action (-r) performed. No analysis target specified."
    exit 0
fi

# Validate target folder (now we know an analysis is expected)
if [[ -z "$TARGET_DIR" ]]; then
    log "ERROR" "No target folder specified for analysis."
    usage
fi
if [[ ! -e "$TARGET_DIR" ]]; then
    log "ERROR" "The target folder (or file) '$TARGET_DIR' does not exist."
    exit 1
fi
if [[ ! -r "$TARGET_DIR" ]]; then
    log "ERROR" "The target folder (or file) '$TARGET_DIR' is not readable (check permissions)."
    exit 1
fi

# Determine which script to run and its specific arguments
SCRIPT_TO_RUN_PATH=""
declare -a SCRIPT_ARGS=()

case "$ANALYSIS_MODE" in
    light)
        SCRIPT_TO_RUN_PATH="${SRC_DIR}/light_mode.sh"
        SCRIPT_ARGS+=("$TARGET_DIR")
        log "INFO" "Light mode selected. Logging is handled by light_mode.sh. MAIN_LOG_DIR='${MAIN_LOG_DIR:-not set}' is exported for information."
        ;;
    medium)
        SCRIPT_TO_RUN_PATH="${SRC_DIR}/medium_mode.sh"
        SCRIPT_ARGS+=("$TARGET_DIR")
        log "INFO" "Medium mode selected. Logging is handled by medium_mode.sh. MAIN_LOG_DIR='${MAIN_LOG_DIR:-not set}' is exported for information."
        ;;
    heavy)
        SCRIPT_TO_RUN_PATH="${SRC_DIR}/linav.sh"
        SCRIPT_ARGS+=("--path" "$TARGET_DIR")
        if [[ -n "$MAIN_LOG_DIR" ]]; then
            export LOG_FILE="$MAIN_LOG_DIR/heavy_mode_scan.log"
            log "INFO" "Heavy mode: LOG_FILE exported as '$LOG_FILE' for linav.sh."
        fi
        if ${FORK_MODE} || ${MULTITHREAD_SIMULATION}; then
            SCRIPT_ARGS+=("--exec" "fork")
            log "INFO" "Heavy mode: Added --exec fork option (enabled by -f or -t)."
        fi
        ;;
    *)
        log "ERROR" "Analysis mode '$ANALYSIS_MODE' not handled (internal script error)."
        exit 1
        ;;
esac

# Check existence and executability of the script to run
if [[ ! -f "$SCRIPT_TO_RUN_PATH" ]]; then
    log "ERROR" "Analysis script '$SCRIPT_TO_RUN_PATH' for mode '$ANALYSIS_MODE' not found."
    exit 1
fi
if [[ ! -x "$SCRIPT_TO_RUN_PATH" ]]; then
    log "ERROR" "Analysis script '$SCRIPT_TO_RUN_PATH' is not executable. Try: chmod +x '$SCRIPT_TO_RUN_PATH'"
    exit 1
fi

log "INFO" "Preparing to execute analysis: '$SCRIPT_TO_RUN_PATH' with arguments: '${SCRIPT_ARGS[*]}'"
echo "Launching analysis (mode: $ANALYSIS_MODE) on target '$TARGET_DIR'..."

COMMAND_TO_EXEC=("$SCRIPT_TO_RUN_PATH" "${SCRIPT_ARGS[@]}")

EXEC_PID=0
SCRIPT_EXIT_CODE=0

if ${SUBSHELL_MODE} && ${FORK_MODE}; then
    log "INFO" "Executing in explicit subshell AND in background."
    ( "${COMMAND_TO_EXEC[@]}" ) &
    EXEC_PID=$!
elif ${SUBSHELL_MODE}; then
    log "INFO" "Executing in explicit subshell (foreground)."
    ( "${COMMAND_TO_EXEC[@]}" )
    SCRIPT_EXIT_CODE=$?
elif ${FORK_MODE}; then
    log "INFO" "Executing in background."
    "${COMMAND_TO_EXEC[@]}" &
    EXEC_PID=$!
else
    log "INFO" "Executing in foreground."
    "${COMMAND_TO_EXEC[@]}"
    SCRIPT_EXIT_CODE=$?
fi

if [[ $EXEC_PID -ne 0 ]]; then
    log "INFO" "Analysis script '$SCRIPT_TO_RUN_PATH' launched in background with PID: $EXEC_PID."
    echo "Analysis (mode: $ANALYSIS_MODE) launched in background (PID: $EXEC_PID). Check logs for progress."
else
    log "INFO" "Analysis script '$SCRIPT_TO_RUN_PATH' finished with exit code: $SCRIPT_EXIT_CODE."
    if [[ $SCRIPT_EXIT_CODE -ne 0 ]]; then
        log "WARN" "The analysis script (mode: $ANALYSIS_MODE) appears to have encountered errors (exit code: $SCRIPT_EXIT_CODE)."
        echo "Analysis (mode: $ANALYSIS_MODE) appears to have encountered errors (code: $SCRIPT_EXIT_CODE)."
    else
        echo "Analysis (mode: $ANALYSIS_MODE) completed successfully."
    fi
fi

log "INFO" "Script $SCRIPT_NAME finished."
exit $SCRIPT_EXIT_CODE
