#!/bin/bash
#
# WireGuard installer + Squid addon (Ubuntu-only)
# Final cleaned script prepared for a fresh installation
#
set -euo pipefail

# Simple helpers
err() { echo "ERROR: $*" >&2; }
info() { echo "$*"; }

# Ensure running under bash
if readlink /proc/$$/exe | grep -q "dash"; then
  err 'This installer needs to be run with "bash", not "sh".'
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  err "Run with sudo or as root."
  exit 1
fi

# OS check: Ubuntu only (>=22.04)
if ! grep -qs "ubuntu" /etc/os-release; then
  err "This installer supports Ubuntu only."
  exit 1
fi
os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
if [[ "$os_version" -lt 2204 ]]; then
  err "Ubuntu 22.04 or newer required."
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default variables to avoid unbound variable errors under set -u
dns=""
wg_net_base=""
wg_server=""
wg_server_ip=""
wg_ipv4_subnet=""
ip=""
ip6=""
public_ip=""
port=""
client=""
boringtun_updates=""

pause() { read -n1 -r -p "Press any key to continue..." || true; echo; }

# Validate simple IPv4 / CIDR input
validate_ipv4_cidr() {
  local input="$1"
  if [[ ! "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]{1,2}))?$ ]]; then
    return 1
  fi
  local ipaddr=${input%%/*}
  local prefix=${input#*/}
  if [[ "$ipaddr" == "$prefix" ]]; then prefix=""; fi
  IFS='.' read -r o1 o2 o3 o4 <<< "$ipaddr"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    if ! [[ "$o" =~ ^[0-9]+$ ]]; then return 1; fi
    if (( o < 0 || o > 255 )); then return 1; fi
  done
  if [[ -n "$prefix" ]]; then
    if ! [[ "$prefix" =~ ^[0-9]+$ ]]; then return 1; fi
    if (( prefix < 1 || prefix > 32 )); then return 1; fi
  fi
  return 0
}

# Ensure wg_net_base and wg_ipv4_subnet are initialized (derive from /etc/wireguard/wg0.conf if present)
ensure_wg_net_base() {
  if [[ -n "${wg_net_base:-}" ]]; then
    return 0
  fi
  if [[ -f /etc/wireguard/wg0.conf ]]; then
    installed_addr=$(grep -m1 '^Address' /etc/wireguard/wg0.conf | sed 's/ //g' | cut -d'=' -f2 | cut -d',' -f1 || true)
    if validate_ipv4_cidr "$installed_addr"; then
      [[ "$installed_addr" != */* ]] && installed_addr="${installed_addr}/24"
      wg_server="$installed_addr"
      wg_server_ip="${wg_server%%/*}"
      wg_net_base="$(echo "$wg_server_ip" | cut -d. -f1-3)"
      wg_ipv4_subnet="${wg_net_base}.0/24"
      return 0
    fi
  fi
  # Fallback default
  wg_net_base="10.7.0"
  wg_ipv4_subnet="${wg_net_base}.0/24"
}

# DNS selection used for client configs
new_client_dns() {
  echo "Select a DNS server for the client:"
  echo "   1) Default system resolvers"
  echo "   2) Google (8.8.8.8)"
  echo "   3) Cloudflare (1.1.1.1)"
  echo "   4) OpenDNS"
  echo "   5) Quad9"
  echo "   6) Gcore"
  echo "   7) AdGuard"
  echo "   8) Specify custom resolvers"
  read -p "DNS server [1]: " dns_choice
  until [[ -z "$dns_choice" || "$dns_choice" =~ ^[1-8]$ ]]; do
    echo "$dns_choice: invalid selection."
    read -p "DNS server [1]: " dns_choice
  done
  case "$dns_choice" in
    1|"")
      if grep -qv '127.0.0.53' /etc/resolv.conf 2>/dev/null; then
        resolv_conf="/etc/resolv.conf"
      else
        resolv_conf="/run/systemd/resolve/resolv.conf"
      fi
      dns=$(grep -v '^#\|^;' "$resolv_conf" 2>/dev/null | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g' || echo "1.1.1.1")
    ;;
    2) dns="8.8.8.8, 8.8.4.4" ;;
    3) dns="1.1.1.1, 1.0.0.1" ;;
    4) dns="208.67.222.222, 208.67.220.220" ;;
    5) dns="9.9.9.9, 149.112.112.112" ;;
    6) dns="95.85.95.85, 2.56.220.2" ;;
    7) dns="94.140.14.14, 94.140.15.15" ;;
    8)
      until [[ -n "${custom_dns:-}" ]]; do
        read -p "Enter DNS servers (comma or space separated): " dns_input
        dns_input=$(echo "$dns_input" | tr ',' ' ')
        custom_dns=""
        for dns_ip in $dns_input; do
          if [[ "$dns_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
            if [[ -z "$custom_dns" ]]; then
              custom_dns="$dns_ip"
            else
              custom_dns="${custom_dns}, $dns_ip"
            fi
          fi
        done
        if [[ -z "$custom_dns" ]]; then
          echo "Invalid input."
        else
          dns="$custom_dns"
        fi
      done
    ;;
  esac
  : "${dns:=1.1.1.1}"
  echo "Using DNS: $dns"
}

# ---------------- Squid management ----------------
manage_squid_users() {
  local passfile="/etc/squid/passwd"
  while true; do
    clear
    echo "Squid user management:"
    echo "  1) Add user"
    echo "  2) Remove user"
    echo "  3) List users"
    echo "  4) Back"
    read -p "Choice [1-4]: " su_choice
    case "$su_choice" in
      1)
        read -p "Username: " uname
        while true; do
          read -s -p "Password: " upass; echo
          read -s -p "Confirm: " upass2; echo
          [[ "$upass" == "$upass2" ]] && break
          echo "Passwords do not match."
        done
        if command -v htpasswd >/dev/null 2>&1; then
          if htpasswd -h 2>&1 | grep -q '\-B'; then
            htpasswd -bB "$passfile" "$uname" "$upass"
          else
            htpasswd -b "$passfile" "$uname" "$upass"
          fi
          chown proxy: "$passfile" 2>/dev/null || chown root: "$passfile" 2>/dev/null || true
          chmod 640 "$passfile" 2>/dev/null || true
          echo "User $uname added."
        else
          err "htpasswd not found. Install apache2-utils."
        fi
        pause
      ;;
      2)
        read -p "Username to remove: " runame
        if [[ -f "$passfile" ]]; then
          if command -v htpasswd >/dev/null 2>&1; then
            htpasswd -D "$passfile" "$runame" 2>/dev/null || sed -i "/^${runame}:/d" "$passfile"
          else
            sed -i "/^${runame}:/d" "$passfile"
          fi
          echo "User $runame removed (if existed)."
        else
          echo "No password file at $passfile"
        fi
        pause
      ;;
      3)
        if [[ -f "$passfile" ]]; then
          echo "Users:"; cut -d: -f1 "$passfile" || true
        else
          echo "No users configured."
        fi
        pause
      ;;
      4) return ;;
      *) echo "Invalid choice." ;;
    esac
  done
}

# --- вставляемая функция: create_proxy_user() ---
create_proxy_user() {
  local USERNAME="$1"
  local PASSWORD="$2"
  local DEFER="${3:-}"

  if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    echo "Usage: create_proxy_user USERNAME PASSWORD [defer]"
    return 1
  fi

  # Ensure htpasswd exists
  if ! command -v htpasswd >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y
      apt-get install -y apache2-utils
    elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
      if command -v yum >/dev/null 2>&1; then
        yum install -y httpd-tools
      else
        dnf install -y httpd-tools
      fi
    else
      echo "Please install apache2-utils/httpd-tools manually."
      return 1
    fi
  fi

  mkdir -p /etc/squid

  local passfile="/etc/squid/passwd"
  if [ ! -f "$passfile" ]; then
    htpasswd -cb "$passfile" "$USERNAME" "$PASSWORD"
  else
    htpasswd -b "$passfile" "$USERNAME" "$PASSWORD"
  fi

  # determine squid runtime user
  SQUID_USER=""
  SQUID_USER=$(ps -eo user,comm | awk '/[s]quid|[p]roxy/ { print $1; exit }' 2>/dev/null || true)
  if [ -z "$SQUID_USER" ]; then
    if id -u proxy >/dev/null 2>&1; then
      SQUID_USER=proxy
    elif id -u squid >/dev/null 2>&1; then
      SQUID_USER=squid
    else
      SQUID_USER=root
    fi
  fi

  chown "$SQUID_USER":"$SQUID_USER" "$passfile" 2>/dev/null || true
  chmod 640 "$passfile"

  # systemd override to ensure ordering with squid-iptables.service
  mkdir -p /etc/systemd/system/squid.service.d
  cat > /etc/systemd/system/squid.service.d/override.conf <<'EOF'
[Unit]
Wants=squid-iptables.service
After=squid-iptables.service
EOF

  # If caller requested defer, skip service reloads
  if [ "$DEFER" = "defer" ]; then
    echo "Proxy user '$USERNAME' added/updated (deferred service reload)."
    return 0
  fi

  systemctl daemon-reload || true
  systemctl restart squid >/dev/null 2>&1 || systemctl reload squid >/dev/null 2>&1 || true
  systemctl enable --now squid-iptables.service >/dev/null 2>&1 || true
  systemctl restart squid-iptables.service >/dev/null 2>&1 || true
  systemctl restart squid >/dev/null 2>&1 || true

  echo "Proxy user '$USERNAME' added/updated and services reloaded/enabled."
}
# --- конец вставляемой функции ---

install_squid_interactive() {
  read -p "Install and configure Squid proxy? [Y/n]: " do_squid
  [[ -z "$do_squid" ]] && do_squid="y"
  if [[ ! "$do_squid" =~ ^[yY]$ ]]; then return; fi

  # Ensure WG variables exist so we can build ACL for WG clients if needed
  ensure_wg_net_base

  local default_bind_ip="${public_ip:-$ip}"
  read -p "IP address to bind Squid to [${default_bind_ip}]: " squid_bind_ip
  [[ -z "$squid_bind_ip" ]] && squid_bind_ip="${default_bind_ip}"
  read -p "Squid listen port [3128]: " squid_port
  [[ -z "$squid_port" ]] && squid_port="3128"

  apt-get update
  apt-get install -y squid apache2-utils fail2ban || true

  # Find auth helper (basic_ncsa_auth). If missing, we'll install squid package or fallback to disabling auth in config.
  auth_prog="$(command -v basic_ncsa_auth || true)"
  if [[ -z "${auth_prog}" ]]; then
    if [[ -x /usr/lib/squid/basic_ncsa_auth ]]; then
      auth_prog="/usr/lib/squid/basic_ncsa_auth"
    elif [[ -x /usr/lib64/squid/basic_ncsa_auth ]]; then
      auth_prog="/usr/lib64/squid/basic_ncsa_auth"
    else
      auth_prog=""
    fi
  fi

  if [[ -n "$auth_prog" ]]; then
    auth_enabled=1
  else
    auth_enabled=0
    echo "WARNING: basic_ncsa_auth helper not found. Squid will be configured without basic auth for non-WG clients."
  fi

  [[ -f /etc/squid/passwd ]] || { touch /etc/squid/passwd; chmod 640 /etc/squid/passwd; chown proxy: /etc/squid/passwd 2>/dev/null || chown root: /etc/squid/passwd 2>/dev/null || true; }

  read -p "Create initial proxy user now? [Y/n]: " create_proxy_user
  [[ -z "$create_proxy_user" ]] && create_proxy_user="y"
  if [[ "$create_proxy_user" =~ ^[yY]$ && $auth_enabled -eq 1 ]]; then
    while true; do read -p "Proxy username: " proxy_user; [[ -n "$proxy_user" ]] && break; done
    while true; do
      read -s -p "Proxy password: " proxy_pass; echo
      read -s -p "Confirm password: " proxy_pass2; echo
      [[ "$proxy_pass" == "$proxy_pass2" ]] && break
      echo "Mismatch."
    done
    # Use create_proxy_user so ownership/htpasswd/systemd reload is handled consistently
    create_proxy_user "$proxy_user" "$proxy_pass"
  elif [[ "$create_proxy_user" =~ ^[yY]$ && $auth_enabled -eq 0 ]]; then
    echo "Skipping user creation because auth helper is not available."
  fi

  [[ -f /etc/squid/squid.conf ]] && cp /etc/squid/squid.conf /etc/squid/squid.conf.orig || true

  # Build auth block depending on helper presence
  if [[ "$auth_enabled" -eq 1 ]]; then
    read -r -d '' auth_block <<EOF || true
# Authentication helper (basic NCSA)
auth_param basic program ${auth_prog} /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Proxy
auth_param basic credentialsttl 1 hour
acl authenticated proxy_auth REQUIRED
EOF
    http_access_for_auth="http_access allow authenticated"
  else
    auth_block=""
    http_access_for_auth=""
  fi

  # Generate squid.conf: listen on all interfaces so WG clients can reach it via tunnel IP
  cat > /etc/squid/squid.conf <<EOF
# Minimal Squid config created by installer (adjusted)
# Listen on all interfaces so WG clients and public clients can connect
http_port 0.0.0.0:${squid_port}

${auth_block}
# WireGuard subnet - allowed without auth (replace if you have a different WG subnet)
acl wg_net src ${wg_ipv4_subnet}

# Standard safe ports and CONNECT handling
acl Safe_ports port 80        # http
acl Safe_ports port 443       # https
acl Safe_ports port 21        # ftp
acl Safe_ports port 70        # gopher
acl Safe_ports port 1025-65535
acl CONNECT method CONNECT

# Access rules (order matters)
# Allow WG clients first (optionally without auth)
http_access allow wg_net
${http_access_for_auth}

# Deny CONNECT to non-safe ports
http_access deny CONNECT !Safe_ports

# Default deny
http_access deny all

access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log
cache_store_log none

cache_mem 64 MB
maximum_object_size_in_memory 64 KB
maximum_object_size 16 MB

visible_hostname squid-server
EOF

  systemctl enable --now squid || systemctl restart squid || true

  if systemctl is-active --quiet firewalld.service; then
    firewall-cmd --add-port="${squid_port}/tcp"
    firewall-cmd --permanent --add-port="${squid_port}/tcp"
  else
    local iptables_path
    iptables_path=$(command -v iptables || echo /sbin/iptables)
    cat > /etc/systemd/system/squid-iptables.service <<UNIT
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
# Allow connections to squid port from any destination address
ExecStart=${iptables_path} -w 5 -I INPUT -p tcp --dport ${squid_port} -j ACCEPT
ExecStop=${iptables_path} -w 5 -D INPUT -p tcp --dport ${squid_port} -j ACCEPT
# Explicitly allow WG subnet (if present) to reach the proxy port
ExecStart=${iptables_path} -w 5 -I INPUT -s ${wg_ipv4_subnet} -p tcp --dport ${squid_port} -j ACCEPT
ExecStop=${iptables_path} -w 5 -D INPUT -s ${wg_ipv4_subnet} -p tcp --dport ${squid_port} -j ACCEPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now squid-iptables.service || true
  fi

  if command -v fail2ban-server >/dev/null 2>&1; then
    cat > /etc/fail2ban/filter.d/squid.conf <<FF
[Definition]
failregex = ^<HOST> .*TCP_DENIED/407 .*
ignoreregex =
FF
    cat > /etc/fail2ban/jail.d/squid.local <<JJ
[squid]
enabled = true
filter = squid
port = ${squid_port}
protocol = tcp
logpath = /var/log/squid/access.log
maxretry = 3
findtime = 600
bantime = 3600
action = iptables[name=Squid, port="${squid_port}", protocol=tcp]
JJ
    systemctl restart fail2ban || true
  fi

  echo "Squid installed and configured on 0.0.0.0:${squid_port} (WG subnet: ${wg_ipv4_subnet})"
  pause
}

uninstall_squid() {
  if [[ ! -f /etc/squid/squid.conf && ! $(systemctl list-unit-files | grep -q squid) ]]; then
    echo "Squid does not appear to be installed/configured by this script."
    pause
    return
  fi
  read -p "Confirm removal of Squid and related files? [y/N]: " rem
  if [[ ! "$rem" =~ ^[yY]$ ]]; then echo "Aborted."; pause; return; fi

  systemctl stop squid.service 2>/dev/null || true
  systemctl disable squid.service 2>/dev/null || true
  systemctl stop squid-iptables.service 2>/dev/null || true
  systemctl disable squid-iptables.service 2>/dev/null || true
  rm -f /etc/systemd/system/squid-iptables.service 2>/dev/null || true
  systemctl daemon-reload || true

  rm -f /etc/fail2ban/filter.d/squid.conf /etc/fail2ban/jail.d/squid.local 2>/dev/null || true
  systemctl restart fail2ban 2>/dev/null || true

  apt-get remove --purge -y squid || true
  rm -rf /etc/squid /var/log/squid /var/cache/squid 2>/dev/null || true
  echo "Squid and related config removed."
  pause
}

# ---------------- WireGuard helpers ----------------
new_client_setup() {
  ensure_wg_net_base

  local octet=2
  # find next free octet
  while grep AllowedIPs /etc/wireguard/wg0.conf 2>/dev/null | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
    (( octet++ ))
  done
  if [[ "$octet" -eq 255 ]]; then
    err "Subnet full."
    return 1
  fi
  local key psk
  key=$(wg genkey)
  psk=$(wg genpsk)
  cat <<EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< "$key")
PresharedKey = $psk
AllowedIPs = ${wg_net_base}.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf 2>/dev/null && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF

  cat > "$script_dir/$client.conf" <<EOF
[Interface]
Address = ${wg_net_base}.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf 2>/dev/null && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = ${dns:-1.1.1.1}
PrivateKey = $key

[Peer]
PublicKey = $(grep '^PrivateKey' /etc/wireguard/wg0.conf | head -n1 | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | head -n1 | cut -d " " -f 3):$(grep ListenPort /etc/wireguard/wg0.conf | head -n1 | cut -d " " -f 3)
PersistentKeepalive = 25
EOF
}

remove_wireguard_full() {
  read -p "Confirm complete removal of WireGuard (configs, packages)? [y/N]: " rr
  if [[ ! "$rr" =~ ^[yY]$ ]]; then echo "Aborted."; pause; return; fi

  systemctl disable --now wg-iptables.service 2>/dev/null || true
  rm -f /etc/systemd/system/wg-iptables.service 2>/dev/null || true
  systemctl disable --now wg-quick@wg0.service 2>/dev/null || true
  rm -f /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf 2>/dev/null || true
  rm -f /etc/sysctl.d/99-wireguard-forward.conf 2>/dev/null || true
  apt-get remove --purge -y wireguard wireguard-tools qrencode || true
  rm -rf /etc/wireguard || true
  echo "WireGuard removed."
  pause
}

# ---------------- Main installer flow ----------------
main_wireguard_install_flow() {
  if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
    echo "Installing wget for script..."
    apt-get update
    apt-get install -y wget
  fi

  clear
  echo "WireGuard installer (Ubuntu)"
  # choose public IP/interface
  if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
    ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f1 | grep -oE '[0-9.]+')
  else
    number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
    echo "Which IPv4 address should be used?"
    ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f1 | grep -oE '[0-9.]+' | nl -s ') '
    read -p "IPv4 address [1]: " ip_number
    [[ -z "$ip_number" ]] && ip_number="1"
    ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f1 | grep -oE '[0-9.]+' | sed -n "${ip_number}p")
  fi

  # If private IP, ask for public
  if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
    echo "This server seems behind NAT. Public IPv4 or hostname?"
    get_public_ip=$(grep -m1 -oE '^[0-9.]+$' <<< "$(wget -T 10 -t1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m10 -4Ls "http://ip1.dynupdate.no-ip.com/")" || true)
    read -p "Public IPv4 / hostname [${get_public_ip}]: " public_ip
    [[ -z "$public_ip" ]] && public_ip="$get_public_ip"
  fi

  # minimal IPv6 detect
  if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
    ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f1 | grep -oE '([0-9a-fA-F:]+)')
  fi

  read -p "What port should WireGuard listen on? [51820]: " port
  [[ -z "$port" ]] && port="51820"

  echo "Enter WireGuard tunnel server IPv4 (CIDR). Example: 10.7.0.1/24"
  read -p "Tunnel IPv4 [10.7.0.1/24]: " wg_server_input
  [[ -z "$wg_server_input" ]] && wg_server_input="10.7.0.1/24"
  until validate_ipv4_cidr "$wg_server_input"; do
    echo "Invalid format."
    read -p "Tunnel IPv4 [10.7.0.1/24]: " wg_server_input
    [[ -z "$wg_server_input" ]] && wg_server_input="10.7.0.1/24"
  done
  [[ "$wg_server_input" != */* ]] && wg_server_input="${wg_server_input}/24"
  prefix=${wg_server_input#*/}
  if [[ "$prefix" != "24" ]]; then
    echo "Forcing /24 for compatibility."
    ip_only=${wg_server_input%%/*}
    wg_server_input="${ip_only}/24"
  fi
  wg_server="$wg_server_input"
  wg_server_ip="${wg_server%%/*}"
  wg_net_base="$(echo "$wg_server_ip" | cut -d. -f1-3)"
  wg_ipv4_subnet="${wg_net_base}.0/24"

  read -p "Enter a name for the first client [client]: " unsanitized_client
  client=$(sed 's/[^0-9a-zA-Z_-]/_/g' <<< "${unsanitized_client:-client}" | cut -c-15)
  [[ -z "$client" ]] && client="client"

  new_client_dns

  apt-get update
  apt-get install -y wireguard qrencode iptables || true

  if [[ -n "${ip6:-}" ]]; then ip6_part=", fddd:2c4:2c4:2c4::1/64"; else ip6_part=""; fi

  cat > /etc/wireguard/wg0.conf <<EOF
# Do not alter the commented lines
# ENDPOINT ${public_ip:-$ip}

[Interface]
Address = ${wg_server}${ip6_part}
PrivateKey = $(wg genkey)
ListenPort = ${port}

EOF
  chmod 600 /etc/wireguard/wg0.conf

  echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
  echo 1 > /proc/sys/net/ipv4/ip_forward
  [[ -n "${ip6:-}" ]] && { echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf; echo 1 > /proc/sys/net/ipv6/conf/all/forwarding; }

  iptables_path=$(command -v iptables || echo /sbin/iptables)
  cat > /etc/systemd/system/wg-iptables.service <<UNIT
[Unit]
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=${iptables_path} -w 5 -t nat -A POSTROUTING -s ${wg_ipv4_subnet} ! -d ${wg_ipv4_subnet} -j SNAT --to ${ip}
ExecStart=${iptables_path} -w 5 -I INPUT -p udp --dport ${port} -j ACCEPT
ExecStart=${iptables_path} -w 5 -I FORWARD -s ${wg_ipv4_subnet} -j ACCEPT
ExecStart=${iptables_path} -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=${iptables_path} -w 5 -t nat -D POSTROUTING -s ${wg_ipv4_subnet} ! -d ${wg_ipv4_subnet} -j SNAT --to ${ip}
ExecStop=${iptables_path} -w 5 -D INPUT -p udp --dport ${port} -j ACCEPT
ExecStop=${iptables_path} -w 5 -D FORWARD -s ${wg_ipv4_subnet} -j ACCEPT
ExecStop=${iptables_path} -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now wg-iptables.service || true

  new_client_setup
  systemctl enable --now wg-quick@wg0.service || true

  echo
  qrencode -t ANSI256UTF8 < "$script_dir/$client.conf" 2>/dev/null || true
  echo "Client config written to: $script_dir/$client.conf"
  pause
}

# Top-level menus
while true; do
  clear
  echo "Main menu:"
  echo "  1) WireGuard"
  echo "  2) Squid (proxy)"
  echo "  3) Exit"
  read -p "Choice [1-3]: " main_choice
  case "$main_choice" in
    1)
      if [[ ! -e /etc/wireguard/wg0.conf ]]; then
        main_wireguard_install_flow
      fi
      while true; do
        clear
        echo "WireGuard menu:"
        echo "  1) Add a new WireGuard client"
        echo "  2) Remove an existing WireGuard client"
        echo "  3) List WireGuard clients"
        echo "  4) Remove WireGuard (full)"
        echo "  5) Back"
        read -p "Option: " option
        case "$option" in
          1)
            read -p "Client name: " unsanitized_client
            client=$(sed 's/[^0-9a-zA-Z_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
            while true; do
              if [[ -n "$client" ]] && ! grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf 2>/dev/null; then break; fi
              echo "Invalid or already exists."
              read -p "Client name: " unsanitized_client
              client=$(sed 's/[^0-9a-zA-Z_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
            done
            new_client_dns
            new_client_setup
            wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" /etc/wireguard/wg0.conf)
            echo "Client $client added. Config: $script_dir/$client.conf"
            pause
          ;;
          2)
            number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf || true)
            if [[ "$number_of_clients" -eq 0 ]]; then
              echo "No clients configured."
              pause
              continue
            fi
            echo "Select client to remove:"
            grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
            echo "  0) Back"
            read -p "Client number (0 to go back): " client_number
            if [[ "$client_number" == "0" ]]; then continue; fi
            until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
              echo "Invalid selection."
              read -p "Client number (0 to go back): " client_number
              [[ "$client_number" == "0" ]] && break
            done
            [[ "$client_number" == "0" ]] && continue
            client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "${client_number}p")
            read -p "Confirm removal of $client? [y/N]: " remove
            if [[ "$remove" =~ ^[yY]$ ]]; then
              pubkey=$(sed -n "/^# BEGIN_PEER $client$/,\$p" /etc/wireguard/wg0.conf | grep -m1 PublicKey | awk '{print $3}')
              [[ -n "$pubkey" ]] && wg set wg0 peer "$pubkey" remove || true
              sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" /etc/wireguard/wg0.conf || true
              echo "Client $client removed."
            else
              echo "Aborted."
            fi
            pause
          ;;
          3)
            echo "Clients:"
            grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 || echo "(none)"
            pause
          ;;
          4)
            remove_wireguard_full
          ;;
          5) break ;;
          *) echo "Invalid option." ;;
        esac
      done
    ;;
    2)
      while true; do
        clear
        echo "Squid (proxy) menu:"
        echo "  1) Install/configure Squid"
        echo "  2) Uninstall Squid (remove configs created by script)"
        echo "  3) Manage Squid users"
        echo "  4) Show Squid status"
        echo "  5) Back"
        read -p "Option: " sopt
        case "$sopt" in
          1) install_squid_interactive ;;
          2) uninstall_squid ;;
          3) manage_squid_users ;;
          4)
            systemctl status squid --no-pager || true
            echo
            echo "Squid config: /etc/squid/squid.conf"
            echo "Password file: /etc/squid/passwd"
            pause
          ;;
          5) break ;;
          *) echo "Invalid option." ;;
        esac
      done
    ;;
    3) echo "Bye."; exit 0 ;;
    *) echo "Invalid choice." ;;
  esac
done