#source /etc/linav/linav.conf
log(){
  if [[ "${VERBOSE:-}" == "True" ]]; then 
    echo "[$(date +%D%l:%M:%S)] : $(whoami) : $1 :   $2"
  fi

  echo "["$(date +%F\ %T)"] : $(whoami) : $1 :   $2" >> "${LOG_FILE:-/var/log/linav/history.log}"
}
