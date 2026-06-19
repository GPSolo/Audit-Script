#!/usr/bin/env bash
#
# audit.sh - Linux Security Audit Toolkit
# Automates a baseline security audit: rootkit detection, MAC status,
# SUID/SGID review, auditd coverage, and optional network capture.
#
# Usage:
#   sudo ./audit.sh --full
#   sudo ./audit.sh --quick
#   sudo ./audit.sh --pcap-duration 300
#
set -uo pipefail

# ---------- Config ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="${SCRIPT_DIR}/reports"
BASELINE_FILE="${SCRIPT_DIR}/suid-baseline.txt"
HOST_NAME="$(hostname)"
RUN_DATE="$(date +%Y-%m-%d_%H%M%S)"
REPORT_FILE="${REPORT_DIR}/audit-${HOST_NAME}-${RUN_DATE}.md"

RUN_RKHUNTER=0
RUN_CLAMAV=0
RUN_APPARMOR=0
RUN_SUID=0
RUN_AUDITD=0
RUN_NETWORK=0
PCAP_DURATION=0

FINDINGS=()

# ---------- Helpers ----------
color() { # color "<ansi-code>" "<text>"
    printf "\033[%sm%s\033[0m\n" "$1" "$2"
}

log_finding() {
    # log_finding LEVEL "message"
    local level="$1"; shift
    local msg="$*"
    FINDINGS+=("[$level] $msg")
    case "$level" in
        CRITICAL) color "31" "[CRITICAL] $msg" ;;
        WARN)     color "33" "[WARN] $msg" ;;
        INFO)     color "36" "[INFO] $msg" ;;
        *)        echo "[$level] $msg" ;;
    esac
}

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "This script must be run as root (most checks need elevated access)." >&2
        exit 1
    fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---------- Checks ----------
check_rkhunter() {
    if ! have_cmd rkhunter; then
        log_finding WARN "rkhunter not installed — skipping rootkit scan"
        return
    fi
    echo "Running rkhunter (this can take a few minutes)..."
    local out
    out="$(rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null)"
    if [[ -z "$out" ]]; then
        log_finding INFO "rkhunter: no warnings"
    else
        while IFS= read -r line; do
            [[ -n "$line" ]] && log_finding WARN "rkhunter: $line"
        done <<< "$out"
    fi
}

check_clamav() {
    if ! have_cmd clamscan; then
        log_finding WARN "clamscan not installed — skipping AV scan"
        return
    fi
    echo "Running ClamAV scan of /home and /etc (this can take a while)..."
    local out
    out="$(clamscan -ri --exclude-dir='^/sys' /tmp 2>/dev/null | grep -E "FOUND$")"
    if [[ -z "$out" ]]; then
        log_finding INFO "ClamAV: no infected files found"
    else
        while IFS= read -r line; do
            log_finding CRITICAL "ClamAV: $line"
        done <<< "$out"
    fi
}

check_apparmor() {
    if ! have_cmd aa-status; then
        log_finding WARN "AppArmor not installed/enabled — skipping MAC check"
        return
    fi
    local enforced complain unconfined
    enforced=$(aa-status --enforced 2>/dev/null | wc -l)
    complain=$(aa-status --complaining 2>/dev/null | wc -l)
    unconfined=$(aa-status 2>/dev/null | grep -A1000 "processes are unconfined" | grep -c "^[[:space:]]*/")
    log_finding INFO "AppArmor: ${enforced} profile(s) enforced, ${complain} in complain mode"
    if [[ "$unconfined" -gt 0 ]]; then
        log_finding WARN "AppArmor: ${unconfined} unconfined process(es) running"
    fi
}

check_suid_sgid() {
    echo "Scanning for SUID/SGID binaries (this can take a minute)..."
    local found baseline
    found="$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort)"
    if [[ -f "$BASELINE_FILE" ]]; then
        baseline="$(sort "$BASELINE_FILE")"
    else
        baseline=""
        log_finding WARN "No SUID baseline file at ${BASELINE_FILE} — treating every result as new"
    fi
    while IFS= read -r bin; do
        [[ -z "$bin" ]] && continue
        if ! grep -qxF "$bin" <<< "$baseline"; then
            log_finding WARN "SUID/SGID binary not in baseline allowlist: $bin"
        fi
    done <<< "$found"
}

check_auditd() {
    if ! have_cmd auditctl; then
        log_finding WARN "auditd not installed — skipping audit subsystem check"
        return
    fi
    local rules
    rules="$(auditctl -l 2>/dev/null)"
    if [[ -z "$rules" ]]; then
        log_finding CRITICAL "auditd: no rules loaded"
        return
    fi
    # spot-check a few high-value watches
    grep -q "shadow" <<< "$rules" || log_finding CRITICAL "auditd: no rule watching /etc/shadow"
    grep -q "passwd" <<< "$rules" || log_finding WARN "auditd: no rule watching /etc/passwd"
    grep -q "execve" <<< "$rules" || log_finding WARN "auditd: no rule watching execve syscalls"
    log_finding INFO "auditd: $(wc -l <<< "$rules") rule(s) loaded"
}

check_network() {
    if [[ "$PCAP_DURATION" -le 0 ]]; then
        return
    fi
    if ! have_cmd tcpdump; then
        log_finding WARN "tcpdump not installed — skipping network capture"
        return
    fi
    local pcap_file="${REPORT_DIR}/capture-${HOST_NAME}-${RUN_DATE}.pcap"
    echo "Capturing traffic for ${PCAP_DURATION}s -> ${pcap_file}"
    timeout "${PCAP_DURATION}" tcpdump -i any -w "$pcap_file" 2>/dev/null
    local conn_count
    conn_count=$(tcpdump -r "$pcap_file" 2>/dev/null | wc -l)
    log_finding INFO "Network capture: ${conn_count} packet(s) over ${PCAP_DURATION}s, saved to $(basename "$pcap_file")"
    if tcpdump -r "$pcap_file" -nn port 21 or port 23 or port 80 2>/dev/null | grep -q .; then
        log_finding WARN "Network capture: traffic seen on plaintext protocol ports (FTP/Telnet/HTTP) — review pcap manually"
    fi
}

# ---------- Report ----------
generate_report() {
    mkdir -p "$REPORT_DIR"
    {
        echo "# Security Audit Report"
        echo
        echo "- Host: \`${HOST_NAME}\`"
        echo "- Date: $(date)"
        echo
        echo "## Findings"
        echo
        if [[ ${#FINDINGS[@]} -eq 0 ]]; then
            echo "No checks were run."
        else
            for f in "${FINDINGS[@]}"; do
                echo "- $f"
            done
        fi
    } > "$REPORT_FILE"
    echo
    echo "Report written to ${REPORT_FILE}"
}

# ---------- Argument parsing ----------
usage() {
    cat <<EOF
Usage: $0 [--full|--quick] [--pcap-duration SECONDS]

  --full              Run all checks (rkhunter, clamav, apparmor, suid, auditd)
  --quick             Run rkhunter + SUID audit only
  --pcap-duration N   Capture N seconds of traffic and include in the audit
EOF
    exit 1
}

[[ $# -eq 0 ]] && usage

while [[ $# -gt 0 ]]; do
    case "$1" in
        --full)
            RUN_RKHUNTER=1; RUN_CLAMAV=1; RUN_APPARMOR=1; RUN_SUID=1; RUN_AUDITD=1
            shift ;;
        --quick)
            RUN_RKHUNTER=1; RUN_SUID=1
            shift ;;
        --pcap-duration)
            PCAP_DURATION="${2:-0}"
            RUN_NETWORK=1
            shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done

# ---------- Main ----------
require_root

[[ "$RUN_RKHUNTER" -eq 1 ]] && check_rkhunter
[[ "$RUN_CLAMAV" -eq 1 ]] && check_clamav
[[ "$RUN_APPARMOR" -eq 1 ]] && check_apparmor
[[ "$RUN_SUID" -eq 1 ]] && check_suid_sgid
[[ "$RUN_AUDITD" -eq 1 ]] && check_auditd
[[ "$RUN_NETWORK" -eq 1 ]] && check_network

generate_report
