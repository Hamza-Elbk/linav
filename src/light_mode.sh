#!/bin/bash

# ============================================================================
# Light Mode Scanner Module - Lightweight antivirus scanning functionality
# ============================================================================
# This module provides lightweight file scanning capabilities that can be
# integrated into other scripts or used standalone.
# ============================================================================

# Global variables with defaults
LIGHT_SCANNER_CONFIG_LOADED=${LIGHT_SCANNER_CONFIG_LOADED:-false}
LIGHT_SCANNER_MAX_FILESIZE=${LIGHT_SCANNER_MAX_FILESIZE:-10M}
LIGHT_SCANNER_QUARANTINE_DIR=${LIGHT_SCANNER_QUARANTINE_DIR:-"/var/quarantine/linav"}
LIGHT_SCANNER_VERBOSE=${LIGHT_SCANNER_VERBOSE:-false}

# Counters for reporting
declare -A LIGHT_SCANNER_STATS=(
    [files_scanned]=0
    [files_suspicious]=0
    [files_quarantined]=0
    [files_ignored]=0
    [vt_detections]=0
    [heuristic_detections]=0
)

# Configuration arrays for flexibility
declare -a LIGHT_SCANNER_ARCHIVE_EXTENSIONS=(zip rar 7z tar gz bz2 xz)
declare -a LIGHT_SCANNER_SUSPICIOUS_EXTENSIONS=(exe txt bat sh vbs scr js py msi cmd ps1 jar dll vbe cpl hta reg wsf gadget psm1)
declare -a LIGHT_SCANNER_DANGEROUS_PATTERNS=(
    'rm[[:space:]]+-rf[[:space:]]+/'
    'wget[[:space:]]'
    'curl[[:space:]]'
    'nc[[:space:]]'
    'bash[[:space:]]'
    'chmod[[:space:]][0-7]{3}[[:space:]]'
    '\|[[:space:]]*bash[[:space:]]*$'
)
# ============================================================================
# Configuration and Initialization Functions
# ============================================================================

# Initialize the light scanner module
light_scanner_init() {
    local config_path="${1:-/etc/linav/linav.conf}"
    local utils_path="${2:-$(dirname "${BASH_SOURCE[0]}")/utils/logit.sh}"
    
    # Source configuration if not already loaded
    if [[ "$LIGHT_SCANNER_CONFIG_LOADED" != "true" ]]; then
        if [[ -f "$config_path" ]]; then
            source "$config_path"
            LIGHT_SCANNER_CONFIG_LOADED=true
        else
            echo "WARN: Configuration file not found at $config_path" >&2
        fi
        
        # Source logging utility
        if [[ -f "$utils_path" ]]; then
            source "$utils_path"
        else
            echo "WARN: Logging utility not found at $utils_path" >&2
            # Fallback logging function
            log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1: $2" >&2; }
        fi
    fi
    
    # Create necessary directories
    if [[ -n "$LOG_FILE" ]]; then
        mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
    fi
    mkdir -p "$LIGHT_SCANNER_QUARANTINE_DIR" 2>/dev/null
    chmod 700 "$LIGHT_SCANNER_QUARANTINE_DIR" 2>/dev/null
}

# Reset scanner statistics
light_scanner_reset_stats() {
    LIGHT_SCANNER_STATS[files_scanned]=0
    LIGHT_SCANNER_STATS[files_suspicious]=0
    LIGHT_SCANNER_STATS[files_quarantined]=0
    LIGHT_SCANNER_STATS[files_ignored]=0
    LIGHT_SCANNER_STATS[vt_detections]=0
    LIGHT_SCANNER_STATS[heuristic_detections]=0
}

# Get scanner statistics
light_scanner_get_stats() {
    local format="${1:-json}"
    
    case "$format" in
        "json")
            cat << EOF
{
    "files_scanned": ${LIGHT_SCANNER_STATS[files_scanned]},
    "files_suspicious": ${LIGHT_SCANNER_STATS[files_suspicious]},
    "files_quarantined": ${LIGHT_SCANNER_STATS[files_quarantined]},
    "files_ignored": ${LIGHT_SCANNER_STATS[files_ignored]},
    "vt_detections": ${LIGHT_SCANNER_STATS[vt_detections]},
    "heuristic_detections": ${LIGHT_SCANNER_STATS[heuristic_detections]}
}
EOF
            ;;
        "summary")
            echo "=== Light Scanner Summary ==="
            echo "Files scanned: ${LIGHT_SCANNER_STATS[files_scanned]}"
            echo "Files ignored: ${LIGHT_SCANNER_STATS[files_ignored]}"
            echo "Suspicious files: ${LIGHT_SCANNER_STATS[files_suspicious]}"
            echo "Files quarantined: ${LIGHT_SCANNER_STATS[files_quarantined]}"
            echo "VirusTotal detections: ${LIGHT_SCANNER_STATS[vt_detections]}"
            echo "Heuristic detections: ${LIGHT_SCANNER_STATS[heuristic_detections]}"
            ;;
    esac
}

# ============================================================================
# Core Scanning Functions
# ============================================================================

# Check if file extension should be ignored
light_scanner_is_archive() {
    local extension="$1"
    local ext
    for ext in "${LIGHT_SCANNER_ARCHIVE_EXTENSIONS[@]}"; do
        [[ "$extension" == "$ext" ]] && return 0
    done
    return 1
}

# Check if file extension is suspicious
light_scanner_is_suspicious_extension() {
    local extension="$1"
    local ext
    for ext in "${LIGHT_SCANNER_SUSPICIOUS_EXTENSIONS[@]}"; do
        [[ "$extension" == "$ext" ]] && return 0
    done
    return 1
}

# Perform heuristic analysis on file content
light_scanner_heuristic_check() {
    local file="$1"
    local pattern
    
    # Skip binary files to avoid grep issues
    if ! file "$file" | grep -q "text"; then
        return 1
    fi
    
    for pattern in "${LIGHT_SCANNER_DANGEROUS_PATTERNS[@]}"; do
        if grep -qE "$pattern" "$file" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

# VirusTotal scan function
light_scanner_virustotal_check() {
    local file="$1"
    local sha256
    local vt_response
    local malicious_count
    
    [[ -z "$VIRUSTOTAL_API_KEY" ]] && return 1
    
    sha256=$(sha256sum "$file" | awk '{print $1}')
    
    vt_response=$(curl -s --max-time 30 --request GET \
        --url "https://www.virustotal.com/api/v3/files/$sha256" \
        --header "x-apikey: $VIRUSTOTAL_API_KEY")
    
    if echo "$vt_response" | jq -e '.error' &>/dev/null; then
        log WARN "VirusTotal: File not found in VT database"
        return 2
    fi
    
    malicious_count=$(echo "$vt_response" | jq -r '.data.attributes.last_analysis_stats.malicious // 0' 2>/dev/null)
    
    if [[ "$malicious_count" -ge 1 ]]; then
        log INFO "[VT MALWARE] $malicious_count detections for $file"
        ((LIGHT_SCANNER_STATS[vt_detections]++))
        return 0
    else
        log INFO "[VT CLEAN] No detections for $file"
        return 1
    fi
}

# Quarantine a suspicious file
light_scanner_quarantine_file() {
    local file="$1"
    local dest
    local timestamp
    
    timestamp=$(date +%Y%m%d_%H%M%S)
    dest="$LIGHT_SCANNER_QUARANTINE_DIR/$(basename "$file")_$timestamp"
    
    # Ensure quarantine directory exists and has proper permissions
    if ! mkdir -p "$LIGHT_SCANNER_QUARANTINE_DIR"; then
        log ERROR "Cannot create quarantine directory: $LIGHT_SCANNER_QUARANTINE_DIR"
        return 1
    fi
    
    if ! chmod 700 "$LIGHT_SCANNER_QUARANTINE_DIR"; then
        log ERROR "Cannot set permissions on quarantine directory: $LIGHT_SCANNER_QUARANTINE_DIR"
        return 1
    fi
    
    # Move file to quarantine
    if mv "$file" "$dest"; then
        chmod 600 "$dest" 2>/dev/null
        log INFO "[QUARANTINE] $file moved to $dest"
        ((LIGHT_SCANNER_STATS[files_quarantined]++))
        return 0
    else
        log ERROR "[QUARANTINE] Failed to move $file to $dest"
        return 1
    fi
}
# ============================================================================
# Main Scanning Functions
# ============================================================================

# Analyze a single file (main scanning function)
light_scanner_analyze_file() {
    local file="$1"
    local is_suspicious_candidate=false
    local is_confirmed_suspicious=false
    local filename extension perms
    
    # Validate input
    [[ -z "$file" || ! -f "$file" ]] && return 1
    
    ((LIGHT_SCANNER_STATS[files_scanned]++))
    
    filename=$(basename "$file")
    extension="${filename##*.}"
    
    # Skip archive files
    if light_scanner_is_archive "$extension"; then
        log INFO "File ignored (archive): $file"
        ((LIGHT_SCANNER_STATS[files_ignored]++))
        return 0
    fi
    
    # Check for suspicious extensions
    if light_scanner_is_suspicious_extension "$extension"; then
        log INFO "[CHECK] Potentially suspicious extension: $file"
        is_suspicious_candidate=true
    fi
    
    # Check for elevated permissions
    perms=$(stat -c "%a" "$file" 2>/dev/null)
    if [[ "$perms" -ge 755 ]]; then
        log INFO "[CHECK] Elevated permissions ($perms): $file"
        is_suspicious_candidate=true
    fi
    
    # Check for double extensions
    if [[ "$filename" =~ \.(exe|sh|bat|py|js)\.[^.]*$ ]]; then
        log INFO "[CHECK] Suspicious double extension: $file"
        is_suspicious_candidate=true
    fi
    
    # Check for files without extensions
    if [[ "$filename" != *.* ]]; then
        log INFO "[CHECK] File without extension: $file"
        is_suspicious_candidate=true
    fi
    
    # Perform detailed scans only on suspicious candidates
    if [[ "$is_suspicious_candidate" == true ]]; then
        ((LIGHT_SCANNER_STATS[files_suspicious]++))
        
        # Heuristic analysis
        if light_scanner_heuristic_check "$file"; then
            log INFO "[HEURISTIC] Dangerous command detected in $file"
            is_confirmed_suspicious=true
            ((LIGHT_SCANNER_STATS[heuristic_detections]++))
        fi
        
        # VirusTotal check (if API key available)
        if light_scanner_virustotal_check "$file"; then
            is_confirmed_suspicious=true
        fi
        
        # Quarantine if confirmed suspicious
        if [[ "$is_confirmed_suspicious" == true ]]; then
            light_scanner_quarantine_file "$file"
        fi
    fi
    
    return 0
}

# Scan a directory or file
light_scanner_scan_target() {
    local target="$1"
    local max_size="${2:-$LIGHT_SCANNER_MAX_FILESIZE}"
    local file_count
    
    # Validate target
    if [[ -z "$target" ]]; then
        log ERROR "No target provided"
        return 100
    fi
    
    if [[ ! -e "$target" ]]; then
        log ERROR "Target not found: $target"
        return 101
    fi
    
    log INFO "Light scan started on $target"
    
    # Handle single file
    if [[ -f "$target" ]]; then
        light_scanner_analyze_file "$target"
        log INFO "Light scan completed"
        return 0
    fi
    
    # Handle directory
    if [[ -d "$target" ]]; then
        file_count=$(find "$target" -type f 2>/dev/null | wc -l)
        
        if [[ "$file_count" -eq 0 ]]; then
            log INFO "No files to analyze in $target"
            return 0
        fi
        
        log INFO "Found $file_count files to scan in $target"
        
        # Process files sequentially
        while IFS= read -r -d '' file; do
            [[ "$LIGHT_SCANNER_VERBOSE" == "true" ]] && log INFO "Analyzing: $file"
            light_scanner_analyze_file "$file"
        done < <(find "$target" -type f ! -size +"${max_size}" -print0 2>/dev/null)
        
        log INFO "Light scan completed"
        return 0
    fi
    
    log ERROR "Invalid target type: $target"
    return 102
}

# ============================================================================
# Utility Functions
# ============================================================================

# Set scanner configuration
light_scanner_configure() {
    local key="$1"
    local value="$2"
    
    case "$key" in
        "max_filesize")
            LIGHT_SCANNER_MAX_FILESIZE="$value"
            ;;
        "quarantine_dir")
            LIGHT_SCANNER_QUARANTINE_DIR="$value"
            mkdir -p "$LIGHT_SCANNER_QUARANTINE_DIR" 2>/dev/null
            ;;
        "verbose")
            LIGHT_SCANNER_VERBOSE="$value"
            ;;
        "add_suspicious_ext")
            LIGHT_SCANNER_SUSPICIOUS_EXTENSIONS+=("$value")
            ;;
        "add_archive_ext")
            LIGHT_SCANNER_ARCHIVE_EXTENSIONS+=("$value")
            ;;
        "add_danger_pattern")
            LIGHT_SCANNER_DANGEROUS_PATTERNS+=("$value")
            ;;
        *)
            log ERROR "Unknown configuration key: $key"
            return 1
            ;;
    esac
}

# Show help information
light_scanner_help() {
    cat << 'EOF'
Light Scanner Module - Usage Guide

FUNCTIONS:
  light_scanner_init [config_path] [utils_path]  - Initialize the scanner
  light_scanner_scan_target <target> [max_size]  - Scan file or directory
  light_scanner_analyze_file <file>              - Analyze single file
  light_scanner_get_stats [format]               - Get scan statistics
  light_scanner_reset_stats                      - Reset statistics
  light_scanner_configure <key> <value>          - Configure scanner
  light_scanner_help                             - Show this help

CONFIGURATION KEYS:
  max_filesize       - Maximum file size to scan (default: 10M)
  quarantine_dir     - Quarantine directory path
  verbose            - Enable verbose logging (true/false)
  add_suspicious_ext - Add suspicious file extension
  add_archive_ext    - Add archive extension to ignore
  add_danger_pattern - Add dangerous pattern for heuristic detection

EXAMPLES:
  # Initialize and scan a directory
  light_scanner_init
  light_scanner_scan_target "/path/to/scan"
  light_scanner_get_stats summary

  # Configure and use
  light_scanner_configure "verbose" "true"
  light_scanner_configure "max_filesize" "50M"
  light_scanner_scan_target "/home/user/downloads"

INTEGRATION:
  Source this file in your script:
    source "/path/to/light_mode.sh"
    light_scanner_init
    light_scanner_scan_target "$TARGET_DIR"
EOF
}

# ============================================================================
# Standalone Script Execution (Backward Compatibility)
# ============================================================================

# Legacy function for backward compatibility
run_scans_light() {
    local target="$1"
    light_scanner_init
    light_scanner_scan_target "$target"
    light_scanner_get_stats summary
}

# Main execution when script is run directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Initialize scanner
    light_scanner_init
    
    # Check for help flag
    if [[ "$1" == "--help" || "$1" == "-h" ]]; then
        light_scanner_help
        exit 0
    fi
    
    # Check for stats flag
    if [[ "$1" == "--stats" ]]; then
        light_scanner_get_stats "${2:-summary}"
        exit 0
    fi
    
    # Get target from command line
    TARGET_PATH="$1"
    
    # Validate target
    if [[ -z "$TARGET_PATH" ]]; then
        echo "Usage: $0 <target_path> [options]" >&2
        echo "       $0 --help" >&2
        echo "       $0 --stats [json|summary]" >&2
        exit 100
    fi
    
    # Set verbose mode if requested
    if [[ "$2" == "--verbose" || "$2" == "-v" ]]; then
        light_scanner_configure "verbose" "true"
    fi
    
    # Run the scan
    light_scanner_scan_target "$TARGET_PATH"
    scan_result=$?
    
    # Show summary
    echo ""
    light_scanner_get_stats summary
    
    # Exit with appropriate code
    exit $scan_result
fi 
