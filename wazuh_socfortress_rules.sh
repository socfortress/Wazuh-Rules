#!/bin/bash
# Installs the SOCFortress ruleset on a Wazuh manager.
#
# Rules and decoders are backed up first. If validation, restart or the
# health check fails, the backup is restored and the script exits non-zero.

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WAZUH_DIR="${WAZUH_DIR:-/var/ossec}"
WAZUH_USER="${WAZUH_USER:-wazuh}"
WAZUH_GROUP="${WAZUH_GROUP:-wazuh}"
RULES_REPO="${RULES_REPO:-https://github.com/socfortress/Wazuh-Rules.git}"
RULES_REF="${RULES_REF:-main}"

SKIP_CONFIRMATION=false
DEBUG=false
TMP_DIR=""
BACKUP_DIR=""

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]
Configure Wazuh with SOCFortress ruleset

Options:
  -y, --yes          Skip confirmation prompt
  -d, --debug        Trace shell commands (set -x)
  -r, --ref REF      Branch, tag or commit of the rules repository (default: $RULES_REF)
  -h, --help         Display this help message

Environment:
  WAZUH_DIR          Wazuh installation directory (default: /var/ossec)
  RULES_REPO         Git URL of the rules repository
EOF
}

timestamp() { date +'%m/%d/%Y %H:%M:%S'; }
log() { echo "$(timestamp) INFO: $*"; }
warn() { echo "$(timestamp) WARNING: $*" >&2; }
err() { echo "$(timestamp) ERROR: $*" >&2; }

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -y|--yes)
                SKIP_CONFIRMATION=true
                ;;
            -d|--debug)
                DEBUG=true
                ;;
            -r|--ref)
                if [[ -z "${2:-}" ]]; then
                    err "$1 requires a value"
                    usage >&2
                    exit 1
                fi
                RULES_REF="$2"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                err "Unknown option: $1"
                usage >&2
                exit 1
                ;;
        esac
        shift
    done
}

require_root() {
    if [[ "$EUID" -ne 0 ]]; then
        err "This script must be run as root."
        exit 1
    fi
}

check_dependencies() {
    if ! command -v git &>/dev/null; then
        err "git could not be found. Install it with your package manager."
        exit 1
    fi
    log "Git package found. Continuing..."
}

check_architecture() {
    local arch
    arch=$(uname -m)
    if [[ "$arch" != "x86_64" ]]; then
        warn "Architecture $arch is not x86_64. The rules are plain XML, so continuing."
    fi
}

manager_package_installed() {
    if command -v dpkg-query &>/dev/null; then
        dpkg-query -W -f='${Status}' wazuh-manager 2>/dev/null | grep -q 'install ok installed'
    elif command -v rpm &>/dev/null; then
        rpm -q wazuh-manager &>/dev/null
    else
        return 1
    fi
}

check_manager() {
    if ! manager_package_installed || [[ ! -x "$WAZUH_DIR/bin/wazuh-control" ]]; then
        err "Wazuh-Manager software could not be found or is not installed in $WAZUH_DIR"
        exit 1
    fi
    if [[ ! -d "$WAZUH_DIR/etc/rules" || ! -d "$WAZUH_DIR/etc/decoders" ]]; then
        err "$WAZUH_DIR/etc/rules or $WAZUH_DIR/etc/decoders is missing"
        exit 1
    fi
}

confirm() {
    if [[ "$SKIP_CONFIRMATION" == true ]]; then
        log "Confirmation skipped with -y flag"
        return 0
    fi

    local yn
    while true; do
        if ! read -r -p "This copies the SOCFortress rule and decoder XML files into $WAZUH_DIR/etc and overwrites files with the same name. A backup of etc/rules and etc/decoders is kept. Continue? (y/n) " yn; then
            echo >&2
            err "No answer on stdin. Run with -y to skip the prompt."
            exit 1
        fi
        case $yn in
            [Yy]*) return 0 ;;
            [Nn]*) log "Aborted by user"; exit 0 ;;
            *) echo "Please answer yes or no." ;;
        esac
    done
}

# Clones the rules repository into the temp dir and checks out the requested ref.
fetch_rules() {
    RULES_SRC="$TMP_DIR/Wazuh-Rules"
    log "Cloning $RULES_REPO"
    if ! git clone --quiet "$RULES_REPO" "$RULES_SRC"; then
        err "Failed to clone SOCFortress rules repository"
        return 1
    fi
    if ! git -C "$RULES_SRC" checkout --quiet "$RULES_REF"; then
        err "Ref '$RULES_REF' not found in $RULES_REPO"
        return 1
    fi
    log "Installing rules at commit $(git -C "$RULES_SRC" rev-parse --short HEAD)"
}

# Builds the install plan: one source file and one destination per XML file.
# Files that declare a <decoder> element go to etc/decoders, the rest to etc/rules.
# Duplicate file names fail here, before anything on the system changes.
collect_files() {
    local file name dest
    local -A seen=()
    PLAN_SRC=()
    PLAN_DST=()

    while IFS= read -r -d '' file; do
        name=$(basename "$file")
        if [[ -n "${seen[$name]:-}" ]]; then
            err "Duplicate file name $name: ${seen[$name]} and $file"
            return 1
        fi
        seen[$name]=$file

        if grep -qE '<decoder[[:space:]>]' "$file"; then
            dest="$WAZUH_DIR/etc/decoders"
        else
            dest="$WAZUH_DIR/etc/rules"
        fi
        PLAN_SRC+=("$file")
        PLAN_DST+=("$dest/$name")
    done < <(find "$RULES_SRC" -path '*/.git' -prune -o -type f -name '*.xml' -print0)

    if (( ${#PLAN_SRC[@]} == 0 )); then
        err "No XML files found in the rules repository"
        return 1
    fi
    log "Planned ${#PLAN_SRC[@]} files"
}

backup_rules() {
    BACKUP_DIR="$WAZUH_DIR/etc/socfortress-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -m 750 "$BACKUP_DIR" || return 1
    cp -a "$WAZUH_DIR/etc/rules" "$WAZUH_DIR/etc/decoders" "$BACKUP_DIR/" || return 1
    log "Backed up etc/rules and etc/decoders to $BACKUP_DIR"
}

# Replaces etc/rules and etc/decoders with the backup copy, so files added by
# this run are removed too. Checks the backup before deleting anything.
restore_backup() {
    if [[ ! -d "$BACKUP_DIR/rules" || ! -d "$BACKUP_DIR/decoders" ]]; then
        err "Backup in $BACKUP_DIR is incomplete, nothing restored"
        return 1
    fi
    warn "Restoring etc/rules and etc/decoders from $BACKUP_DIR"
    local dir
    for dir in rules decoders; do
        if ! { rm -rf -- "${WAZUH_DIR:?}/etc/$dir" && cp -a -- "$BACKUP_DIR/$dir" "$WAZUH_DIR/etc/$dir"; }; then
            err "Restore of etc/$dir failed. Copy $BACKUP_DIR/$dir back by hand."
            return 1
        fi
    done
}

install_rules() {
    local i
    for i in "${!PLAN_SRC[@]}"; do
        install -m 660 -o "$WAZUH_USER" -g "$WAZUH_GROUP" -- "${PLAN_SRC[$i]}" "${PLAN_DST[$i]}" || return 1
    done
}

validate_rules() {
    log "Validating rules and decoders with wazuh-analysisd -t"
    "$WAZUH_DIR/bin/wazuh-analysisd" -t
}

restart_manager() {
    log "Restarting wazuh-manager"
    if [[ -d /run/systemd/system ]] && command -v systemctl &>/dev/null; then
        systemctl restart wazuh-manager.service
    else
        "$WAZUH_DIR/bin/wazuh-control" restart
    fi
}

# Lists the daemons wazuh-control status reports as running, one per line.
# Optional daemons (clusterd, maild, ...) report "not running" on a stock
# manager, so health is judged against the set that ran before the install.
running_daemons() {
    local status
    status=$("$WAZUH_DIR/bin/wazuh-control" status 2>&1)
    sed -n 's/^\([^ ]*\) is running.*/\1/p' <<<"$status"
}

health_check() {
    log "Waiting 20 seconds for daemons to start"
    sleep 20

    local running daemon
    local -a missing=()
    running=$(running_daemons)
    for daemon in wazuh-analysisd "${RUNNING_BEFORE[@]}"; do
        grep -qxF -- "$daemon" <<<"$running" || missing+=("$daemon")
    done

    if (( ${#missing[@]} > 0 )); then
        err "Wazuh-Manager is not healthy. Not running after restart: ${missing[*]}"
        "$WAZUH_DIR/bin/wazuh-control" status >&2 2>&1
        err "Check $WAZUH_DIR/logs/ossec.log for details."
        return 1
    fi

    log "Wazuh-Manager Service is healthy. Thanks for checking us out :)"
    log "Get started with our free-for-life tier here: https://www.socfortress.co/trial.html Happy Defending!"
}

# Logs the reason, restores the backup and exits 1. Pass "restart" to restart
# the manager after the restore, so it runs the old rules again.
rollback() {
    err "$1"
    if ! restore_backup; then
        err "Automatic restore failed. Restore from $BACKUP_DIR manually."
    elif [[ "${2:-}" == "restart" ]] && ! restart_manager; then
        err "Restart after restore failed. Check $WAZUH_DIR/logs/ossec.log."
    fi
    exit 1
}

main() {
    parse_args "$@"
    if [[ "$DEBUG" == true ]]; then
        set -x
    fi

    require_root
    check_dependencies
    check_architecture
    check_manager
    confirm

    TMP_DIR=$(mktemp -d) || exit 1
    trap 'rm -rf -- "$TMP_DIR"' EXIT

    fetch_rules || exit 1
    collect_files || exit 1

    if ! backup_rules; then
        err "Backup failed. No files were changed."
        exit 1
    fi
    "$WAZUH_DIR/bin/wazuh-control" info >"$BACKUP_DIR/wazuh-info.txt" 2>&1 \
        || warn "wazuh-control info failed. Version not saved."

    mapfile -t RUNNING_BEFORE < <(running_daemons)
    log "Running before install: ${RUNNING_BEFORE[*]:-none}"

    install_rules || rollback "Failed to install rules"
    validate_rules || rollback "Rules failed wazuh-analysisd -t validation"
    restart_manager || rollback "Could not restart wazuh-manager" restart
    health_check || rollback "Wazuh-Manager health check failed" restart

    log "Installation process completed"
}

# BASH_SOURCE is empty when the script is piped into bash, so ${BASH_SOURCE[0]:-$0}
# still matches $0 and main runs.
if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
    main "$@"
fi
