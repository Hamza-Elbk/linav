#!/usr/bin/bash
SCRIPT_DIR="$(cd ..  && pwd)"
source "$SCRIPT_DIR"/src/utils/logit.sh
source /etc/linav/linav.conf
send_report_email() {
  local report_file="$1"
  local recipient_mail="${REPORT_EMAIL:-bikahamaa@gmail.com}" # Should be set in linav.conf
  local subject="[Linav] Scan Summary Report - $(date '+%Y-%m-%d %H:%M:%S')"

  if [[ -z "$recipient_mail" ]]; then
    log INFO "No REPORT_EMAIL configured in linav.conf. Skipping email of summary report."
    return 0
  fi

  if command -v mailx >/dev/null 2>&1; then
    mailx -s "$subject" "$recipient_mail" < "$report_file" && \
      log INFO "Summary report emailed to $recipient_mail using mailx." || \
      log WARN "Failed to send summary report to $recipient_mail using mailx."
  elif command -v mail >/dev/null 2>&1; then
    mail -s "$subject" "$recipient_mail" < "$report_file" && \
      log INFO "Summary report emailed to $recipient_mail using mail." || \
      log WARN "Failed to send summary report to $recipient_mail using mail."
  else
    log WARN "Neither mailx nor mail command found. Cannot send summary report email."
    return 1
  fi
}

send_report_email "/var/log/linav/linav_summary_20250516_213111.txt"