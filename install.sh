#!/usr/bin/env bash
# fmmon installer: everything needed for `./fmmon` to run unprivileged.
#
# Installs four things:
#   1. /usr/local/bin/fmmon                      the binary, on PATH
#   2. /usr/local/bin/fmmon-grant-cap           root helper polkit authorises
#   3. net.spoofer.grantcap.policy + 50-fmmon.rules   the polkit policy
#   4. capabilities on xtables-nft-multi and tc, so the iptables and tc children
#      inherit CAP_NET_ADMIN without the GUI running as root
#
# The binary itself needs no capability up front: on first run it asks polkit
# for CAP_NET_RAW and re-execs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/packaging"
BIN_SRC="$SCRIPT_DIR/bin/fmmon"

GRANT_CAP=/usr/local/bin/fmmon-grant-cap
POLICY=/usr/share/polkit-1/actions/net.spoofer.grantcap.policy
RULES=/etc/polkit-1/rules.d/50-fmmon.rules
AGENT=/usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

ok()   { printf "${GREEN}[OK]${NC}   %s\n" "$1"; }
warn() { printf "${YELLOW}[!]${NC}   %s\n" "$1"; }
die()  { printf "${RED}[ERR]${NC} %s\n" "$1" >&2; exit 1; }

printf "${CYAN}fmmon installer${NC}\n\n"

# ── 1. Build if needed ──────────────────────────────────────────────
if [ ! -f "$BIN_SRC" ]; then
	printf "  No binary found, building...\n"
	command -v wails3 >/dev/null || die "wails3 not on PATH"
	wails3 build || die "build failed"
	[ -f "$BIN_SRC" ] || die "build produced no $BIN_SRC"
fi
ok "binary: $BIN_SRC"

# ── 2. Root-requiring steps ──────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "run this with sudo: sudo ./install.sh"

install -m 0755 "$BIN_SRC" /usr/local/bin/fmmon
ok "installed /usr/local/bin/fmmon"

# The IEEE OUI dataset drives vendor lookup. It has to sit beside the binary
# because ouiFilePath() resolves it relative to the executable.
if [ -f "$SCRIPT_DIR/data/ieee-oui.txt" ]; then
	install -d -m 0755 /usr/local/bin/data
	install -m 0644 "$SCRIPT_DIR/data/ieee-oui.txt" /usr/local/bin/data/ieee-oui.txt
	ok "installed /usr/local/bin/data/ieee-oui.txt"
else
	warn "data/ieee-oui.txt missing - vendor lookup will show 'Unknown'"
fi

install -m 0755 "$SRC_DIR/fmmon-grant-cap" "$GRANT_CAP"
ok "installed $GRANT_CAP (root-owned, not setuid; pkexec supplies root)"

install -m 0644 "$SRC_DIR/net.spoofer.grantcap.policy" "$POLICY"
ok "installed $POLICY"

install -m 0644 "$SRC_DIR/50-fmmon.rules" "$RULES"
ok "installed $RULES"

# iptables and tc are spawned as child processes by the engine. A child of a
# non-root process starts with no capabilities unless it inherits them as
# ambient, and Linux capability sets are per-thread while Go migrates
# goroutines across threads - so ambient cannot work here. Putting
# CAP_NET_ADMIN on the tools themselves is the one approach that holds for every
# exec regardless of which thread forked it.
#
# These are the only parts of the system that keep a privilege after install.
# They are wiped by an iptables/iproute2 package update; rerun this script then.
setcap cap_net_admin=+ep /usr/bin/xtables-nft-multi
setcap cap_net_admin=+ep /usr/bin/tc
ok "granted CAP_NET_ADMIN to xtables-nft-multi and tc"

# ── 3. Polkit agent ──────────────────────────────────────────────────
# Without a running authentication agent polkit has no way to prompt, and
# pkexec fails with "No authentication agent found".
if pgrep -f authentication-agent >/dev/null 2>&1; then
	ok "polkit authentication agent is running"
else
	warn "no polkit authentication agent is running."
	warn "pkexec will fail with 'No authentication agent found' until one runs."
	warn "Start it for this session with:"
	warn "  $AGENT &"
	warn "To make it permanent add to ~/.config/hypr/hyprland.conf:"
	warn "  exec-once = $AGENT"
fi

systemctl reload polkit 2>/dev/null || systemctl restart polkit 2>/dev/null || true

# ── 4. Verify ────────────────────────────────────────────────────────
printf "\n  Verification\n"
getcap /usr/local/bin/fmmon >/dev/null 2>&1 && \
	printf "    %s\n" "$(getcap /usr/local/bin/fmmon)" || \
	printf "    (fmmon has no caps yet - correct, it requests them on first run)"

printf "\n${GREEN}Done.${NC} Run:\n\n"
printf "  ${CYAN}fmmon${NC}\n\n"
printf "  The first launch asks for your password once, then re-execs with\n"
printf "  CAP_NET_RAW and opens the window.\n\n"
printf "  After upgrading fmmon, rerun: ${CYAN}sudo ./install.sh${NC}\n"