#!/bin/bash

# Variables de log
PROGRAM_NAME="scan"
LOG_DIR="/var/log/$PROGRAM_NAME"
LOG_FILE="$LOG_DIR/history.log"
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
# Configuration
TARGET_PATH="$1"
FORK_MODE=0
THREAD_MODE=0
SUBSHELL_MODE=0
MAX_THREADS=4
QUARANTINE_DIR="/var/quarantine/$PROGRAM_NAME"
QUARANTINE_NEEDED=0

# Fonction de log améliorée
logit() {
    level=$1
    shift
    timestamp=$(date +"%Y-%m-%d-%H-%M-%S")
    user=$(whoami)
    message="$*"
    formatted="$timestamp : $user : $level : $message"
    echo "$formatted" | tee -a "$LOG_FILE"
}






# Fonction d'analyse
analyse_fichier_light() {
    local file="$1"
    local is_suspicious_candidate=false
    local is_confirmed_suspicious=false

    filename=$(basename "$file")
    extension="${filename##*.}"
    # ignoré  les fichiers compresse
    case "$extension" in
        zip|rar|7z|tar|gz|bz2|xz)
            logit INFO "Fichier ignoré (archive) : $file"
            return
            ;;
    esac
    
    # extention suspecte cad il va etre scané 
    case "$extension" in
      exe|txt|bat|sh|vbs|scr|js|py|msi|cmd|ps1|jar|dll|vbe|cpl|hta|reg|wsf|gadget|psm1)
        logit INFO "[CHECK] Extension potentiellement suspecte : $file"
        is_suspicious_candidate=true
        ;;
    esac
     # permission élevée cad il va etre scané 
    perms=$(stat -c "%a" "$file")
    if [[ "$perms" -ge 755 ]]; then
        logit INFO "[CHECK] Permissions élevées ($perms) : $file"
        is_suspicious_candidate=true
    fi

    # Vérifie la double extension
    if [[ "$filename" =~ \.(exe|sh|bat|py|js)\.[^.]*$ ]]; then
        logit INFO "[CHECK] Double extension suspecte : $file"
        is_suspicious_candidate=true
    fi

    # Vérifie l'absence d'extension
    if [[ "$filename" != *.* ]]; then
        logit INFO "[CHECK] Fichier sans extension : $file"
        is_suspicious_candidate=true
    fi

#    scan
    if [[ "$is_suspicious_candidate" == true ]]; then
        if grep -qE '(rm[[:space:]]+-rf[[:space:]]+/|wget[[:space:]]|curl[[:space:]]|nc[[:space:]]|bash[[:space:]]|chmod[[:space:]][0-7]{3}[[:space:]]|\|[[:space:]]*bash[[:space:]]*$)' "$file"; then
            logit INFO "[HEURISTIC] Commande dangereuse détectée dans $file"
            is_confirmed_suspicious=true
        fi

     
    #    vuristotal
       VT_API_KEY="c9b5d3d3eb9fa49210ac4898b78ca0b22231c819b251225ec87e416bb114ff0b"
        sha256=$(sha256sum "$file" | awk '{print $1}')

        if [[ -n "$VT_API_KEY" ]]; then
            logit INFO "Vérification VirusTotal pour $file"
            vt_response=$(curl -s --request GET \
                --url "https://www.virustotal.com/api/v3/files/$sha256" \
                --header "x-apikey: $VT_API_KEY")

           
            if echo "$vt_response" | jq -e '.error' &>/dev/null; then
                logit ERROR "VirusTotal : erreur API détectée (limite dépassée ou autre problème)"
            else
                malicious_count=$(echo "$vt_response" | jq -r '.data.attributes.last_analysis_stats.malicious')

                if [[ "$malicious_count" -ge 1 ]]; then
                    logit ERROR "[VT MALWARE] $malicious_count détections pour $file"
                    is_confirmed_suspicious=true
                else
                    logit INFO "[VT CLEAN] Aucune détection pour $file"
                fi
            fi
        else
            logit INFO "Clé API VirusTotal non définie"
        fi
        # clamscan limité juste pour les fichiers <10 M 
        scan_output=$(clamscan --max-filesize=10M --no-summary "$file")
        if echo "$scan_output" | grep -q "FOUND"; then
            logit ERROR "[CLAMAV] $file : $(echo "$scan_output" | cut -d':' -f2-)"
            is_confirmed_suspicious=true
        fi



        # deplacer les fichiers malwares au dossier quarantine
        if [[ "$is_confirmed_suspicious" == true ]]; then
            QUARANTINE_NEEDED=1
            mkdir -p "$QUARANTINE_DIR"
            if [[ $? -ne 0 ]]; then
                logit ERROR "Impossible de créer le dossier de quarantaine : $QUARANTINE_DIR"
                exit 1
            fi
            chmod 700 "$QUARANTINE_DIR"
            if [[ $? -ne 0 ]]; then
                logit ERROR "Impossible de modifier les permissions du dossier de quarantaine : $QUARANTINE_DIR"
                exit 1
            fi

            dest="$QUARANTINE_DIR/$(basename "$file")"

            if mv "$file" "$dest"; then
                chmod 600 "$dest"
                if [[ $? -ne 0 ]]; then
                    logit ERROR "Impossible de changer les permissions du fichier en quarantaine : $dest"
                fi
                logit INFO "[QUARANTINE] $file déplacé vers $dest"
            else
                logit ERROR "[QUARANTINE] Échec du déplacement de $file vers $dest"
            fi

           
        fi
    fi
}

# Gestion des threads (attente de slots disponibles)
wait_for_slot() {
    while [[ $(jobs -rp | wc -l) -ge $MAX_THREADS ]]; do
        sleep 0.2
    done
}

# Fonction principale
run_scans_light() {
    logit INFO "Analyse light commencée sur $TARGET_PATH"

    # si parametre n'est pas forni
    if [[ -z "$TARGET_PATH" ]]; then
        logit ERROR "Aucun chemin fourni. Utilisation : $0 <chemin_cible>"
        exit 100
    fi
    # si Chemin invalide ou introuvable
    if [[ ! -d "$TARGET_PATH" ]]; then
        logit ERROR "Chemin invalide ou introuvable : $TARGET_PATH"
        exit 101
    fi
    # dossier vide 
     local file_count
    file_count=$(find "$TARGET_PATH" -type f | wc -l)

    if [[ "$file_count" -eq 0 ]]; then
        logit INFO "Aucun fichier à analyser dans $TARGET_PATH. Le script démarre et se termine."
        return 0
    fi

    while IFS= read -r -d '' file; do
        logit INFO "Analyse de : $file"
        if [[ "$FORK_MODE" -eq 1 ]]; then
            analyse_fichier_light "$file" &
        elif [[ "$THREAD_MODE" -eq 1 ]]; then
            wait_for_slot
            analyse_fichier_light "$file" &
        else
            analyse_fichier_light "$file"
        fi
    done < <(find "$TARGET_PATH" -type f ! -size +10M -print0)

    if [[ "$FORK_MODE" -eq 1 || "$THREAD_MODE" -eq 1 ]]; then
        wait
    fi

    logit INFO "Analyse light terminée"
}



run_scans_light
