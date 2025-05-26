#!/bin/bash

# ============================================================================
# Medium Mode Scanner Module - Intermediate antivirus scanning functionality
# ============================================================================
# This module provides medium-level file scanning capabilities with ClamAV
# integration.
# ============================================================================

# Global variables with defaults
MEDIUM_SCANNER_CONFIG_LOADED=${MEDIUM_SCANNER_CONFIG_LOADED:-false}
MEDIUM_SCANNER_LOGFILE=${MEDIUM_SCANNER_LOGFILE:-"/var/log/linav/history.log"}

# Statistics tracking
declare -A MEDIUM_SCANNER_STATS=(
    [files_scanned]=0
    [files_found]=0
    [malware_detected]=0
)


# ============================================================================
# Configuration and Initialization Functions
# ============================================================================

# Initialize the medium scanner module
# Purpose: Set up configuration, logging, and required directories
# Parameters: 
#   $1 - config_path (optional, default: /etc/linav/linav.conf)
#   $2 - utils_path (optional, default: auto-detect)
# Returns: 0 on success, 1 on failure
medium_scanner_init() {
    local config_path="${1:-/etc/linav/linav.conf}"
    local utils_path="${2:-$(dirname "${BASH_SOURCE[0]}")/utils/logit.sh}"
    
    # Check if running with sufficient privileges for system logging
    if [[ $EUID -ne 0 ]]; then
        echo "WARN: Not running as root. Some logging features may be limited." >&2
    fi
    
    # Source configuration if not already loaded
    if [[ "$MEDIUM_SCANNER_CONFIG_LOADED" != "true" ]]; then
        if [[ -f "$config_path" ]]; then
            source "$config_path"
            MEDIUM_SCANNER_CONFIG_LOADED=true
        else
            echo "WARN: Configuration file not found at $config_path" >&2
        fi
        
        # Source logging utility
        if [[ -f "$utils_path" ]]; then
            source "$utils_path"
            # Add helper functions that logit.sh doesn't provide
            log_info() { log "INFO" "$1"; }
            log_error() { log "ERROR" "$1"; }
            log_warn() { log "WARN" "$1"; }
        else
            echo "WARN: Logging utility not found at $utils_path" >&2
            # Fallback logging functions for when logit.sh is not available
            log() { 
                local level="$1"
                local message="$2"
                local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
                # Convert VERBOSE to lowercase for case-insensitive comparison
                if [[ "${VERBOSE,,}" == "true" ]]; then 
                    echo "[$timestamp] : $(whoami) : $level : $message"
                fi
                # Try to write to log file if we have permissions
                if [[ -w "$(dirname "${LOG_FILE:-/var/log/linav/history.log}")" ]] 2>/dev/null; then
                    echo "[$timestamp] : $(whoami) : $level : $message" >> "${LOG_FILE:-/var/log/linav/history.log}" 2>/dev/null
                fi
            }
            log_info() { log "INFO" "$1"; }
            log_error() { log "ERROR" "$1"; }
            log_warn() { log "WARN" "$1"; }
        fi
    fi
    
    # Create necessary directories if we have permissions
    if [[ $EUID -eq 0 ]]; then
        mkdir -p "$(dirname "$MEDIUM_SCANNER_LOGFILE")" 2>/dev/null || {
            echo "ERROR: Cannot create log directory $(dirname "$MEDIUM_SCANNER_LOGFILE")" >&2
            return 1
        }
        
        # Create log file if it doesn't exist
        touch "$MEDIUM_SCANNER_LOGFILE" 2>/dev/null || {
            echo "ERROR: Cannot create log file $MEDIUM_SCANNER_LOGFILE" >&2
            echo "Please run with appropriate permissions." >&2
            return 1
        }
    else
        # For non-root users, just warn and continue
        echo "WARN: Running without root privileges. Log files may not be created." >&2
    fi
    
    return 0
}

# Check and install required dependencies
# Purpose: Verify that all required tools are installed and install them if missing
# Parameters: None
# Returns: 0 on success, 102 if sudo required, 103 if apt not available, 1 if critical dependency installation fails
medium_scanner_check_dependencies() {
    local missing_cmds_packages=()

    # Define required commands and their corresponding Debian/Ubuntu packages
    declare -A cmd_to_pkg_map=(
        ["clamscan"]="clamav"
        ["freshclam"]="clamav-freshclam"
        ["find"]="findutils"
        ["date"]="coreutils"
        ["tee"]="coreutils"
        ["grep"]="grep"
    )

    # Check which commands are missing and collect their packages
    for cmd in "${!cmd_to_pkg_map[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_cmds_packages+=("${cmd_to_pkg_map[$cmd]}")
        fi
    done

    # Remove duplicate package names
    local packages_to_install=($(printf "%s\\n" "${missing_cmds_packages[@]}" | sort -u))

    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        log_info "Missing packages for required tools: ${packages_to_install[*]}"
        echo "[INFO] Attempting to install required dependencies automatically..."

        if [[ $EUID -ne 0 ]]; then
            log_error "Installation failed: This script requires sudo privileges to install packages."
            echo "Please run this script with 'sudo'."
            return 102 # Sudo required
        fi

        if ! command -v apt &>/dev/null; then
            log_error "Package manager 'apt' is required but not found. Cannot install dependencies."
            return 103 # apt not available
        fi

        log_info "Updating system package lists (apt update)..."
        if ! apt update > /dev/null; then
            log_error "Failed to update system package lists ('apt update' exited with status $?). This may affect package installation."
        else
            log_info "System package lists updated successfully."
        fi

        log_info "Installing/updating packages: ${packages_to_install[*]}"
        if ! apt install -y "${packages_to_install[@]}" > /dev/null; then
            log_error "Failed to install/update one or more packages: ${packages_to_install[*]}. 'apt install' exited with status $?."
            return 1 # Critical dependency installation failed
        else
            log_info "Packages (${packages_to_install[*]}) installed/updated successfully."
        fi

        log_info "Dependency installation process completed."

        # Post-installation steps for ClamAV (freshclam and service)
        if command -v freshclam &>/dev/null; then
            log_info "Updating ClamAV virus definitions with freshclam..."
            if ! freshclam --quiet; then
                log_error "freshclam update failed (status $?). Check ClamAV logs (e.g., /var/log/clamav/freshclam.log)."
            else
                log_info "ClamAV virus definitions updated successfully via freshclam."
            fi
        else
            log_warn "freshclam command not found even after attempting package installation. Virus definitions may be outdated."
        fi
        
        # Check and manage clamav-freshclam service for automatic updates
        if systemctl list-units --full -all | grep -q 'clamav-freshclam\\.service'; then
            if systemctl is-active --quiet clamav-freshclam.service; then
                log_info "clamav-freshclam.service is active. Restarting to apply any changes..."
                if ! systemctl restart clamav-freshclam.service; then
                    log_warn "Failed to restart clamav-freshclam.service (status $?). Definition updates might not be current."
                else
                    log_info "clamav-freshclam.service restarted."
                fi
            else
                log_info "clamav-freshclam.service is not active. Attempting to start..."
                if ! systemctl start clamav-freshclam.service; then
                    log_warn "Failed to start clamav-freshclam.service (status $?). Automatic updates might be disabled."
                else
                    log_info "clamav-freshclam.service started."
                fi
            fi
            # Ensure the service is enabled to start on boot
            if ! systemctl is-enabled --quiet clamav-freshclam.service; then
                 log_info "Enabling clamav-freshclam.service to start on boot..."
                 if ! systemctl enable clamav-freshclam.service > /dev/null 2>&1; then
                     log_warn "Failed to enable clamav-freshclam.service."
                 else
                     log_info "clamav-freshclam.service enabled."
                 fi
            fi
        else
            log_info "clamav-freshclam.service not found. If clamav-freshclam package was installed, this might indicate a non-standard setup. Manual or cron-based freshclam updates may be needed."
        fi
    else
        log_info "All specified dependencies appear to be installed."
        echo "[INFO] All dependencies are satisfied."
    fi
    
    return 0 # Success
}

# Reset scanner statistics
# Purpose: Clear all scanning statistics counters
# Parameters: None
# Returns: Always 0
medium_scanner_reset_stats() {
    MEDIUM_SCANNER_STATS[files_scanned]=0
    MEDIUM_SCANNER_STATS[files_found]=0
    MEDIUM_SCANNER_STATS[malware_detected]=0
    return 0
}

# Get scanner statistics
# Purpose: Retrieve current scanning statistics in specified format
# Parameters:
#   $1 - format (optional, default: "json", options: "json", "summary")
# Returns: Always 0
medium_scanner_get_stats() {
    local format="${1:-json}"
    
    case "$format" in
        "json")
            cat << EOF
{
    "files_scanned": ${MEDIUM_SCANNER_STATS[files_scanned]},
    "files_found": ${MEDIUM_SCANNER_STATS[files_found]},
    "malware_detected": ${MEDIUM_SCANNER_STATS[malware_detected]}
}
EOF
            ;;
        "summary")
            echo "=== Medium Scanner Summary ==="
            echo "Files scanned: ${MEDIUM_SCANNER_STATS[files_scanned]}"
            echo "Suspicious files found: ${MEDIUM_SCANNER_STATS[files_found]}"
            echo "Malware detected: ${MEDIUM_SCANNER_STATS[malware_detected]}"
            ;;
    esac
    return 0
}

# ============================================================================
# Core Scanning Functions
# ============================================================================

# Find suspicious files in target directory
# Purpose: Search for potentially suspicious files based on extensions
# Parameters:
#   $1 - target_directory (required)
# Returns: 0 on success, 1 if directory not found
medium_scanner_find_suspicious_files() {
    local target_dir="$1"
    
    # Validate target directory
    if [[ ! -d "$target_dir" ]]; then
        log_error "Target directory not found: $target_dir"
        return 1
    fi
    
    # Search for suspicious file types (all files, regardless of modification time)
    find "$target_dir" -type f \( \
        -name "*.sh" -o \
        -name "*.exe" -o \
        -name "*.bat" -o \
        -name "*.dll" -o \
        -name "*.vbs" -o \
        -name "*.ps1" -o \
        -name "*.cmd" -o \
        -name "*.jar" \
    \) 2>/dev/null
    
    return 0
}

# Scan a single file with ClamAV
# Purpose: Perform antivirus scanning on a single file using ClamAV
# Parameters:
#   $1 - file_path (required)
# Returns: 0 if malware found, 1 if clean, 2 if scan error
medium_scanner_scan_file() {
    local file="$1"
    local clamscan_output
    local clamscan_exit_code
    
    # Validate file exists
    if [[ ! -f "$file" ]]; then
        log_error "File not found for scanning: $file"
        return 2 # Scan error: file not found
    fi
    
    ((MEDIUM_SCANNER_STATS[files_scanned]++))
    log_info "Scanning file: $file"
    
    # Perform ClamAV scan.
    # --infected: Only print infected files.
    # --no-summary: Do not print summary statistics.
    # Capture both stdout and stderr to get all messages from clamscan.
    clamscan_output=$(clamscan --infected --no-summary "$file" 2>&1)
    clamscan_exit_code=$?
    
    # Clamscan exit codes:
    # 0: No virus found.
    # 1: Virus(es) found.
    # Other values (e.g., 2, 40-63): Error.
    
    if [[ $clamscan_exit_code -eq 1 ]]; then
        log "WARN" "Malware detected in: $file"
        log_info "ClamAV output for $file: $clamscan_output"
        ((MEDIUM_SCANNER_STATS[malware_detected]++))
        return 0 # Malware found
    elif [[ $clamscan_exit_code -eq 0 ]]; then
        log_info "File is clean: $file"
        return 1 # File is clean
    else
        log_error "Error scanning file $file with ClamAV. Exit code: $clamscan_exit_code"
        log_error "ClamAV output for $file: $clamscan_output"
        return 2 # Scan error
    fi
}

# ============================================================================
# Main Scanning Functions
# ============================================================================

# Run comprehensive medium-level scan
# Purpose: Perform complete medium-level scanning with ClamAV
# Parameters:
#   $1 - target_directory (required)
# Returns: 0 on success, 1 if no files found, 2 on error
medium_scanner_run_scan() {
    local target_dir="$1"
    local -a suspicious_files
    local file
    local files_found=0
    
    # Validate target directory
    if [[ -z "$target_dir" ]]; then
        log_error "No target directory provided"
        return 2
    fi
    
    if [[ ! -d "$target_dir" ]]; then
        log_error "Target directory not found: $target_dir"
        return 2
    fi
    
    log_info "Starting MEDIUM mode scan on: $target_dir"
    # Find suspicious files using mapfile
    mapfile -t suspicious_files < <(medium_scanner_find_suspicious_files "$target_dir")
    
    # Filter out empty lines that might be returned
    local -a filtered_files=()
    for file in "${suspicious_files[@]}"; do
        if [[ -n "$file" && -f "$file" ]]; then
            filtered_files+=("$file")
        fi
    done
    
    # Update statistics with actual found files
    files_found=${#filtered_files[@]}
    MEDIUM_SCANNER_STATS[files_found]=$files_found
    
    if [[ $files_found -eq 0 ]]; then
        log_info "No suspicious files found in $target_dir"
        return 1
    fi
    
    log_info "Found $files_found suspicious files to scan"
    
    # Debug: Print found files if in verbose mode
    if [[ "${VERBOSE,,}" == "true" ]]; then
        log_info "Files to scan:"
        for file in "${filtered_files[@]}"; do
            log_info "  - $file"
        done
    fi
    
    # Scan each suspicious file
    for file in "${filtered_files[@]}"; do
        medium_scanner_scan_file "$file"
    done
    
    log_info "Medium scan completed"
    return 0
}

# Configure scanner settings
# Purpose: Set scanner configuration parameters at runtime
# Parameters:
#   $1 - key (required)
#   $2 - value (required)
# Returns: 0 on success, 1 on invalid key
medium_scanner_configure() {
    local key="$1"
    local value="$2"
    
    case "$key" in
        "logfile")
            MEDIUM_SCANNER_LOGFILE="$value"
            mkdir -p "$(dirname "$MEDIUM_SCANNER_LOGFILE")" 2>/dev/null
            ;;
        *)
            log_error "Unknown configuration key: $key"
            return 1
            ;;
    esac
    return 0
}

# Show help information
# Purpose: Display comprehensive usage information and function documentation
# Parameters: None
# Returns: Always 0
medium_scanner_help() {
    cat << 'EOF'
Medium Scanner Module - Usage Guide

FUNCTIONS:
  medium_scanner_init [config_path] [utils_path]    - Initialize the scanner
  medium_scanner_check_dependencies                 - Check and install dependencies
  medium_scanner_run_scan <target_dir>              - Run comprehensive scan
  medium_scanner_find_suspicious_files <dir>        - Find suspicious files
  medium_scanner_scan_file <file_path>              - Scan single file with ClamAV
  medium_scanner_get_stats [format]                 - Get scan statistics
  medium_scanner_reset_stats                        - Reset statistics
  medium_scanner_configure <key> <value>            - Configure scanner
  medium_scanner_help                               - Show this help

CONFIGURATION KEYS:
  logfile            - Set log file path

STATISTICS:
  files_scanned      - Total files processed by ClamAV
  files_found        - Suspicious files found by search
  malware_detected   - Files flagged as malicious by ClamAV

EXAMPLES:
  # Initialize and run basic scan
  medium_scanner_init
  medium_scanner_run_scan "/home/user/downloads"
  medium_scanner_get_stats summary

  # Configure and run targeted scan
  medium_scanner_configure "logfile" "/var/log/my_scan.log"
  medium_scanner_run_scan "/var/www"
  
  # Check dependencies before use
  medium_scanner_check_dependencies
  medium_scanner_run_scan "/tmp"

INTEGRATION:
  Source this file in your script:
    source "/path/to/medium_mode.sh"
    medium_scanner_init
    medium_scanner_run_scan "$TARGET_DIR"
EOF
    return 0
}

# ============================================================================
# Standalone Script Execution (Backward Compatibility)
# ============================================================================

# Legacy function for backward compatibility
# Purpose: Maintain compatibility with old script interface
# Parameters:
#   $1 - target_directory (required)
# Returns: Same as medium_scanner_run_scan
run_scans_medium() {
    local target_dir="$1"
    medium_scanner_init
    medium_scanner_run_scan "$target_dir"
    medium_scanner_get_stats summary
}

# Main execution when script is run directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Initialize scanner
    medium_scanner_init
    
    # Check for help flag
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        medium_scanner_help
        exit 0
    fi
    
    # Check for stats flag
    if [[ "${1:-}" == "--stats" ]]; then
        medium_scanner_get_stats "${2:-summary}"
        exit 0
    fi
    
    # Get target from command line
    TARGET_PATH="${1:-}"
    
    # Validate target
    if [[ -z "$TARGET_PATH" ]]; then
        echo "Usage: $0 <target_path> [options]" >&2
        echo "       $0 --help" >&2
        echo "       $0 --stats [json|summary]" >&2
        exit 100
    fi
    
    # Check dependencies first
    medium_scanner_check_dependencies || exit $?
    
    # Run the scan
    medium_scanner_run_scan "$TARGET_PATH"
    scan_result=$?
    
    # Show summary
    echo ""
    medium_scanner_get_stats summary
    
    # Exit with appropriate code
    exit $scan_result
fi