#!/bin/bash
# Codex CLI – adaptive firewall initialiser
#
#  ▸ Default  : strict egress-whitelist (original behaviour)
#  ▸ Override : set CODEX_FIREWALL_MODE=off  → no restrictions
#               set CODEX_FIREWALL_MODE=strict (or unset) → whitelist mode
#               set CODEX_FIREWALL_MODE=permissive        → INPUT/OUTPUT ACCEPT but keep ipset list*
#               *permissive currently behaves the same as 'strict' except
#                that default INPUT/OUTPUT policies are ACCEPT instead of DROP.
#
#  ▸ To add or override domains without a file, export
#       CODEX_ALLOWED_DOMAINS="github.com,registry.npmjs.org,crates.io"
#
#  NOTE: run as root (the Dockerfile copies the script and keeps root only while
#        installing/initialising).

set -euo pipefail
IFS=$'\n\t'

MODE="${CODEX_FIREWALL_MODE:-strict}"

###########################################################
# 0. Helper: fully disable the firewall when requested
###########################################################
if [[ "$MODE" == "off" ]]; then
  echo "[codex-firewall] MODE=off  →  disabling all firewall rules."
  for table in filter nat mangle; do
    iptables -t "$table" -F || true
    iptables -t "$table" -X || true
  done
  ipset destroy allowed-domains 2>/dev/null || true
  iptables -P INPUT   ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT  ACCEPT
  echo "[codex-firewall] All traffic now permitted."
  exit 0
fi

###########################################################
# 1. Build the allowed-domains list
###########################################################
ALLOWED_DOMAINS_FILE="/etc/codex/allowed_domains.txt"
ALLOWED_DOMAINS=()

if [[ -f "$ALLOWED_DOMAINS_FILE" ]]; then
  while IFS= read -r domain; do
    [[ -n "$domain" ]] && ALLOWED_DOMAINS+=("$domain")
  done < "$ALLOWED_DOMAINS_FILE"
  echo "Using domains from file: ${ALLOWED_DOMAINS[*]}"
fi

# Append domains passed via env-var
if [[ -n "${CODEX_ALLOWED_DOMAINS:-}" ]]; then
  IFS=',' read -ra EXTRA <<< "${CODEX_ALLOWED_DOMAINS}"
  ALLOWED_DOMAINS+=("${EXTRA[@]}")
fi

# Fallback defaults if still empty
if [[ ${#ALLOWED_DOMAINS[@]} -eq 0 ]]; then
  ALLOWED_DOMAINS=(
    "api.openai.com"
    "github.com" "raw.githubusercontent.com"
    "registry.npmjs.org" "registry.yarnpkg.com"
    "crates.io" "static.crates.io"
    "pypi.org" "files.pythonhosted.org"
  )
  echo "Domains file/env missing; using built-ins: ${ALLOWED_DOMAINS[*]}"
fi

###########################################################
# 2. Flush any pre-existing rules / sets
###########################################################
for table in filter nat mangle; do
  iptables -t "$table" -F || true
  iptables -t "$table" -X || true
done
ipset destroy allowed-domains 2>/dev/null || true

###########################################################
# 3. Baseline rules (DNS & loopback always allowed)
###########################################################
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT  -p udp --sport 53 -j ACCEPT
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

###########################################################
# 4. Create ipset & resolve allowed domains
###########################################################
ipset create allowed-domains hash:net

for domain in "${ALLOWED_DOMAINS[@]}"; do
  echo "Resolving $domain..."
  ips=$(dig +short A "$domain")
  if [[ -z "$ips" ]]; then
    echo "WARNING: $domain did not resolve – skipping"
    continue
  fi
  while read -r ip; do
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || {
      echo "WARNING: Non-IPv4 result $ip for $domain – skipping"
      continue
    }
    ipset add allowed-domains "$ip" || true
  done < <(echo "$ips")
done

###########################################################
# 5. Host network allowance (so docker-in-docker works)
###########################################################
HOST_IP=$(ip route | awk '/default/ {print $3; exit}')
if [[ -n "$HOST_IP" ]]; then
  HOST_NET=$(echo "$HOST_IP" | sed 's|\.[0-9]\+$|.0/24|')
  iptables -A INPUT  -s "$HOST_NET" -j ACCEPT
  iptables -A OUTPUT -d "$HOST_NET" -j ACCEPT
fi

###########################################################
# 6. Policy defaults & stateful rules
###########################################################
if [[ "$MODE" == "permissive" ]]; then
  iptables -P INPUT   ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT  ACCEPT
else
  iptables -P INPUT   DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT  DROP
fi

iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Egress whitelist
iptables -A OUTPUT -m set --match-set allowed-domains dst -j ACCEPT

# Fail-fast rejects (nice TCP reset / ICMP)
for CHAIN in INPUT OUTPUT FORWARD; do
  iptables -A "$CHAIN" -p tcp -j REJECT --reject-with tcp-reset
  iptables -A "$CHAIN" -p udp -j REJECT --reject-with icmp-port-unreachable
done

echo "[codex-firewall] Configuration complete (mode=$MODE)"
