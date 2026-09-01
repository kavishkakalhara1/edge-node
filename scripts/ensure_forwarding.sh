#!/usr/bin/env bash
set -euo pipefail

HOTSPOT=${IOT_GUARD_HOTSPOT_INTERFACE:-wlan0}
UPLINK=${IOT_GUARD_CLOUD_UPLINK_INTERFACE:-eth0}
WEB_PORT=${IOT_GUARD_WEB_PORT:-8080}
UPLINK_RATE_MBIT=${IOT_GUARD_UPLINK_RATE_MBIT:-$(cat "/sys/class/net/$UPLINK/speed" 2>/dev/null || echo 100)}
MANAGEMENT_RATE_MBIT=${IOT_GUARD_MANAGEMENT_RATE_MBIT:-10}

if [[ $HOTSPOT == "$UPLINK" ]]; then
  echo "Hotspot and upstream must use different interfaces." >&2
  exit 1
fi
if [[ ! $WEB_PORT =~ ^[0-9]+$ ]] || (( WEB_PORT < 1 || WEB_PORT > 65535 )); then
  echo "Dashboard port must be between 1 and 65535." >&2
  exit 1
fi
if [[ ! $UPLINK_RATE_MBIT =~ ^[0-9]+$ ]] || \
   [[ ! $MANAGEMENT_RATE_MBIT =~ ^[0-9]+$ ]] || \
   (( MANAGEMENT_RATE_MBIT < 1 || MANAGEMENT_RATE_MBIT >= UPLINK_RATE_MBIT )); then
  echo "Management bandwidth must be positive and below the uplink rate." >&2
  exit 1
fi
for interface in "$HOTSPOT" "$UPLINK"; do
  if [[ ! -e /sys/class/net/$interface ]]; then
    echo "Required forwarding interface $interface is not present." >&2
    exit 1
  fi
done

iptables -C FORWARD -i "$HOTSPOT" -o "$UPLINK" -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -i "$HOTSPOT" -o "$UPLINK" -j ACCEPT
iptables -C FORWARD -i "$UPLINK" -o "$HOTSPOT" \
  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 2 -i "$UPLINK" -o "$HOTSPOT" \
    -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

iptables -N IOT_GUARD_MANAGEMENT 2>/dev/null || true
iptables -F IOT_GUARD_MANAGEMENT
iptables -A IOT_GUARD_MANAGEMENT -i lo -p tcp --dport "$WEB_PORT" -j ACCEPT
iptables -A IOT_GUARD_MANAGEMENT -i "$UPLINK" -p tcp --dport "$WEB_PORT" -j ACCEPT
iptables -A IOT_GUARD_MANAGEMENT -p tcp --dport "$WEB_PORT" \
  -j REJECT --reject-with tcp-reset
iptables -A IOT_GUARD_MANAGEMENT -j RETURN
iptables -C INPUT -j IOT_GUARD_MANAGEMENT 2>/dev/null || \
  iptables -I INPUT 1 -j IOT_GUARD_MANAGEMENT

DEFAULT_RATE_MBIT=$((UPLINK_RATE_MBIT - MANAGEMENT_RATE_MBIT))
tc qdisc delete dev "$UPLINK" root 2>/dev/null || true
tc qdisc add dev "$UPLINK" root handle 1: htb default 20
tc class replace dev "$UPLINK" parent 1: classid 1:1 htb \
  rate "${UPLINK_RATE_MBIT}mbit" ceil "${UPLINK_RATE_MBIT}mbit"
tc class replace dev "$UPLINK" parent 1:1 classid 1:10 htb \
  rate "${MANAGEMENT_RATE_MBIT}mbit" ceil "${UPLINK_RATE_MBIT}mbit" prio 0
tc class replace dev "$UPLINK" parent 1:1 classid 1:20 htb \
  rate "${DEFAULT_RATE_MBIT}mbit" ceil "${UPLINK_RATE_MBIT}mbit" prio 1
tc qdisc replace dev "$UPLINK" parent 1:10 handle 10: fq_codel
tc qdisc replace dev "$UPLINK" parent 1:20 handle 20: fq_codel
tc filter replace dev "$UPLINK" protocol ip parent 1: pref 10 u32 \
  match ip sport "$WEB_PORT" 0xffff flowid 1:10