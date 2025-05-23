#!/bin/bash
set -euo pipefail
shopt -s nullglob

# Charger la configuration dès le début
source /etc/linav/linav.conf

# Définir LOGFILE si non présent dans le .conf
LOGFILE="${LOGFILE:-/var/log/linav/history.log}"

# Chemin du dossier du script
SCRIPT_DIR="$(pwd)"  # ← Correction ici

# Charger les fonctions utilitaires AVANT check_dependencies
source "$SCRIPT_DIR"/utils/logit.sh


# Fichier de log principal
LOGFILE="/var/log/LINAV/history.log"

# Création du répertoire de log si nécessaire
mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null || {
    echo "ERREUR : Impossible de créer le répertoire $(dirname "$LOGFILE")"
    exit 1
}

# Création du fichier log s'il n'existe pas
touch "$LOGFILE" 2>/dev/null || {
    echo "ERREUR : Vous n'avez pas les droits nécessaires pour écrire dans /var/log/LINAV/"
    echo "Veuillez exécuter le script avec sudo."
    exit 1
}


# Fonction de vérification des dépendances
check_dependencies() {
    local missing_deps=()

    declare -A tools=(
        ["clamscan"]="clamav"
        ["freshclam"]="clamav"
        ["mail"]="mailutils"
        ["find"]="findutils"
        ["date"]="coreutils"
        ["tee"]="coreutils"
        ["grep"]="grep"
    )

    for cmd in "${!tools[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("${tools[$cmd]}")
        fi
    done

    # Supprimer les doublons
    missing_deps=($(printf "%s\n" "${missing_deps[@]}" | sort -u))

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_info "Certains outils nécessaires ne sont pas installés : ${missing_deps[*]}"
        echo "[INFO] Installation automatique des dépendances requises..."

        if [[ $EUID -ne 0 ]]; then
            log_error "Installation échouée : Ce script nécessite sudo."
            echo "Veuillez exécuter ce script avec 'sudo'."
            exit 102
        fi

        if ! command -v apt &>/dev/null; then
            log_error "Le gestionnaire de paquets 'apt' est requis."
            exit 103
        fi

        log_info "Mise à jour du système..."
        apt update > /dev/null || {
            log_error "Échec de la mise à jour du système."
            exit 1
        }

        log_info "Installation des dépendances : ${missing_deps[*]}"
        apt install -y "${missing_deps[@]}" > /dev/null || {
            log_error "Échec de l'installation des dépendances."
            exit 1
        }

        log_info "Dépendances installées avec succès."

        if systemctl is-active --quiet clamav-freshclam 2>/dev/null; then
            log_info "Redémarrage du service ClamAV..."
            systemctl restart clamav-freshclam
        else
            log_info "Mise à jour des définitions virales..."
            freshclam > /dev/null
            systemctl start clamav-freshclam && systemctl enable clamav-freshclam > /dev/null 2>&1
        fi
    else
        log_info "Toutes les dépendances sont déjà installées."
        echo "[INFO] Toutes les dépendances sont satisfaites."
    fi
}

# Fonctions de journalisation (déjà chargées via logit.sh)

usage() {
    echo "Usage: $(basename "$0") [OPTIONS] <dossier_cible>"
    echo ""
    echo "Options :"
    echo "  -h, --help                Afficher cette aide et quitter"
    echo "  -p, --path <dir>          Spécifier le dossier cible à analyser (obligatoire)"
    echo "  -m, --mode light|medium|heavy"
    echo "                            Choisir le niveau d'analyse (par défaut: medium)"
    echo "  -f                        Lancer chaque analyse dans un sous-processus (fork)"
    echo "  -t                        Simuler une exécution multithread"
    echo "  -s                        Exécuter dans un sous-shell"
    echo "  -l <dir>                  Activer la journalisation dans le répertoire spécifié"
    echo "  -r                        Réinitialiser les paramètres (réservé admin)"
    echo "  -m medium                 Mode moyen d'analyse"
    echo ""
    echo "Exemple:"
    echo "  ./linav.sh -p /home/user/test-scan -m medium"
    exit 0
}

run_scans_medium() {
    log_info "Démarrage du scan en mode MEDIUM"

    local TARGET_DIR="$1"

    # Recherche des fichiers suspects
    local SUSPICIOUS_FILES=( $(find "$TARGET_DIR" -type f -name "*.sh" -o -name "*.exe" -o -name "*.bat" -o -name "*.dll" -mtime -7) )

    if [[ ${#SUSPICIOUS_FILES[@]} -eq 0 ]]; then
        log_info "Aucun fichier suspect trouvé dans $TARGET_DIR"
        return 0
    fi

    MALWARE_FOUND=false

    for file in "${SUSPICIOUS_FILES[@]}"; do
        log_info "Analyse du fichier : $file"

        if clamscan --no-summary "$file" | grep -q "FOUND"; then
            log_error "Fichier malveillant détecté : $file"
            MALWARE_FOUND=true
        else
            log_info "Fichier propre : $file"
        fi
    done

    if [[ "$MALWARE_FOUND" == true ]]; then
        mail -s "[SECURITY ALERT] Malware trouvé" ouardiaelboujamaai70@gmail.com <<< "ALERTE : Fichiers malveillants détectés !" > /dev/null 2>&1 || \
            log_error "Échec de l'envoi de l'email d'alerte"
    fi
}

# ────────────────────────
# Point d'entrée du script
# ────────────────────────

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage ;;
        -p|--path)
            TARGET_PATH="$2"
            shift ;;
        -m|--mode)
            MODE="$2"
            shift ;;
        -f)
            FORK=1 ;;
        -t)
            THREAD=1 ;;
        -s)
            SUBSHELL=1 ;;
        -l)
            LOGDIR="$2"
            shift ;;
        -r)
            if [[ $EUID -ne 0 ]]; then
                log_error "L'option -r nécessite des privilèges administrateurs."
                exit 102
            fi
            rm -rf /var/log/LINAV/*
            log_info "Paramètres réinitialisés."
            exit 0 ;;
        -*)
            log_error "Option invalide : $1"
            usage ;;
        *)
            TARGET_PATH="$1" ;;
    esac
    shift
done

if [[ -z "${TARGET_PATH:-}" ]]; then
    log_error "Un dossier cible est requis."
    usage
fi

# Appeler la fonction principale
run_scans_medium "$TARGET_PATH"
