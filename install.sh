#! /usr/bin/bash



#TODO : matrix commandes
#TODO : help
#TODO : options 
#TODO : /var/log/linav/reports/
#TODO : configure mail

# Require root access to install packages 
set -euo pipefail   
shopt -s nullglob
required_tools=("clamav" "yara" "parallel" "jq")
PKG_MGR=""
#Create /etc/linav
create_etc_linav(){
    if [[ ! -d /etc/linav ]]; then
     install -d -m 755 /etc/linav
     if [[ -f linav.conf ]] ; then
      install -m 644 linav.conf /etc/linav/
     else 
       
       echo "Warning: linav.conf not found in current directory." >&2
       exit 1
     fi
     
    fi 
}

source ./src/utils/logit.sh
# Check root permession
require_root(){
    if [[ "root" != "$(whoami)" ]] ; then
        echo "[-] Root Permission required " >&2
        exit 1
    fi
}

# detect package manager 
detect_pkg_mgr(){
    for pm in dnf yum zypper apt-get ;do
        command -v "$pm" >/dev/null && { PKG_MGR=$pm; return 0; }
    done
    echo "[-] No supported packet manager detected" >&2
    log "ERROR" "No supported packet manager detected"
    exit 1
}

# install dependecies
install_deps(){
    echo "[*] UPDATING ..."
    log "INFOS" "UPDATING"
    $PKG_MGR update && $PKG_MGR upgrade -y
    for i in "${required_tools[@]}" ; do
        command -v "$i" >/dev/null && continue
        if [[ $i == "clamav" ]] ;then
            command -v clamscan >/dev/null && continue
        fi
        echo "[*] INSTALLING $i ...."
        log "INFOS" "INSTALLING $i ...."
        "$PKG_MGR" install "$i" -y
    done
}


#Create log file
create_logdirectory(){
    if [[ ! -d  /var/log/linav ]]; then
      echo  "INFOS" "Creating /var/log/linav/history.log"
      install -d -m 755 -o root  "/var/log/linav"
      touch "/var/log/linav/history.log"
      chmod 644 "/var/log/linav/history.log"
    fi
    
}

# Install YARA rules from YARA-Rules repository
install_yara_rules() {
    echo "[*] Installing YARA rules..."
    log "INFOS" "Installing YARA rules"
    
    # Create rules directory if it doesn't exist
    if [[ ! -d /etc/linav/rules ]]; then
        echo "[*] Creating /etc/linav/rules directory"
        install -d -m 755 /etc/linav/rules
    fi
    
    # Check if wget and unzip are available
    for tool in wget unzip; do
        if ! command -v "$tool" &>/dev/null; then
            echo "[*] Installing $tool..."
            log "INFOS" "Installing $tool"
            "$PKG_MGR" install "$tool" -y
        fi
    done
    
    # Create a temporary directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR" || { 
        echo "[-] Failed to create temporary directory" >&2
        log "ERROR" "Failed to create temporary directory"
        return 1
    }
    
    # Download YARA rules from GitHub
    echo "[*] Downloading YARA rules from GitHub..."
    log "INFOS" "Downloading YARA rules from GitHub"
    if ! wget -q https://github.com/YARA-Rules/rules/archive/refs/heads/master.zip; then
        echo "[-] Failed to download YARA rules" >&2
        log "ERROR" "Failed to download YARA rules"
        cd - > /dev/null || true
        rm -rf "$TEMP_DIR"
        return 1
    fi
    
    # Unzip the rules
    echo "[*] Extracting YARA rules..."
    log "INFOS" "Extracting YARA rules"
    if ! unzip -q master.zip; then
        echo "[-] Failed to extract YARA rules" >&2
        log "ERROR" "Failed to extract YARA rules"
        cd - > /dev/null || true
        rm -rf "$TEMP_DIR"
        return 1
    fi
    
    # Copy the rules to /etc/linav/rules
    echo "[*] Copying YARA rules to /etc/linav/rules..."
    log "INFOS" "Copying YARA rules to /etc/linav/rules"
    cp -r rules-master/* /etc/linav/rules/
    
    # Generate the combined rules.yar file
    echo "[*] Generating combined rules.yar file..."
    log "INFOS" "Generating combined rules.yar file"
    find /etc/linav/rules -name "*.yar" -not -path "*/deprecated/*" | xargs cat > /etc/linav/rules.yar
    
    # Clean up
    cd - > /dev/null || true
    rm -rf "$TEMP_DIR"
    
    echo "[+] YARA rules installation completed"
    log "INFOS" "YARA rules installation completed"
    return 0
}

main(){
    require_root
    create_etc_linav
    create_logdirectory
    detect_pkg_mgr
    install_deps
    install_yara_rules
}

# wget https://github.com/YARA-Rules/rules/archive/refs/heads/master.zip
#unzip master.zip
#cat rules-master/*/*.yar > /etc/linav/rules.yar
main