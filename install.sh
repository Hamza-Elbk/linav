#! /usr/bin/bash



#TODO : matrix commandes
#TODO : help
#TODO : options 

# Require root access to install packages 
set -euo pipefail   
shopt -s nullglob
required_tools=("clamav" "yara" "parallel")
PKG_MGR=""
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

#Create /etc/linav
create_etc_linav(){
    if [[ ! -d /etc/linav ]]; then
     install -d -m 755 /etc/linav
     if [[ -f linav.conf ]] ; then
      install -m 644 linav.conf /etc/linav/
     else 
       log "ERROR" "linav.conf not found in current directory"
       echo "Warning: linav.conf not found in current directory." >&2
       exit 1
     fi
     
    fi 
}

#Create log file
create_logdirectory(){
    if [[ ! -d  /var/log/linav ]]; then
      log "INFOS" "Creating /var/log/linav/history.log"
      install -d -m 755 -o root  "/var/log/linav"
      touch "/var/log/linav/history.log"
      chmod 644 "/var/log/linav/history.log"
    fi
    
}
main(){
    require_root
    create_etc_linav
    create_logdirectory
    detect_pkg_mgr
    install_deps
    
}

main