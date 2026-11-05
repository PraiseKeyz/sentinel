// The probe that runs on each server. It is POSIX sh, read-only, and prints
// sections that start with "@@name" so parse.ts can split them. It uses
// `sudo -n` (never prompts) when the login user has passwordless sudo, and
// silently skips what it cannot read otherwise.

export function collectorScript(lookbackMinutes: number): string {
  const lb = Math.max(1, Math.floor(lookbackMinutes));
  return `
LB=${lb}
export LC_ALL=C
PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"
if [ "$(id -u)" = 0 ]; then SUDO=root
elif sudo -n true >/dev/null 2>&1; then SUDO=yes
else SUDO=no; fi
# Run privileged when possible. Narrow sudoers rules (only some commands
# allowed) still work: a denied sudo falls back to running unprivileged.
r() {
  if [ "$SUDO" = root ]; then "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo -n "$@" 2>/dev/null || "$@"
  else "$@"; fi
}

echo "@@sudo"; echo "$SUDO"
echo "@@client"; echo "\${SSH_CLIENT%% *}"
echo "@@host"; hostname 2>/dev/null; uname -sr 2>/dev/null; uptime -p 2>/dev/null || uptime
echo "@@cpus"; nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null
echo "@@load"; cat /proc/loadavg 2>/dev/null
echo "@@mem"; grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null
echo "@@disk"; df -P -k -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2
echo "@@tcp"; ss -Htan state established 2>/dev/null | wc -l; ss -Htan state syn-recv 2>/dev/null | wc -l
echo "@@conns"
ss -Htn state established 2>/dev/null | awk '{p=$4; sub(/:[0-9]+$/,"",p); gsub(/\\[|\\]/,"",p); sub(/^::ffff:/,"",p); c[p]++} END{for(k in c) print c[k], k}' | sort -rn | head -n 25
echo "@@listen"; rss -Htlnup 2>/dev/null | awk '{print $1, $5, $7}' | head -n 80

AUTH=$(rjournalctl --since "-\${LB}min" --no-pager -o cat _COMM=sshd _COMM=sshd-session 2>/dev/null)
if [ -z "$AUTH" ]; then
  for f in /var/log/auth.log /var/log/secure; do
    if [ -z "$AUTH" ]; then AUTH=$(rtail -n 4000 "$f" 2>/dev/null); fi
  done
fi
echo "@@failed"
printf '%s\\n' "$AUTH" | grep -E 'Failed (password|publickey|keyboard-interactive)|Invalid user|Connection closed by authenticating user|Did not receive identification|Unable to negotiate|banner exchange|maximum authentication attempts' \\
  | sed -nE 's/.* ([0-9a-fA-F:.]+) port [0-9]+.*/\\1/p' | grep -E '^[0-9a-fA-F:.]*[.:][0-9a-fA-F:.]*$' \\
  | sort | uniq -c | sort -rn | head -n 30
echo "@@accepted"
printf '%s\\n' "$AUTH" | grep -oE 'Accepted [a-z-]+ for [^ ]+ from [0-9a-fA-F:.]+' | awk '{print $4, $6, $2}' | sort -u | head -n 30

echo "@@http"
for f in /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log /var/log/caddy/access.log; do
  if rtest -r "$f" 2>/dev/null; then
    echo "$f"
    rtail -n 20000 "$f" 2>/dev/null | awk '{c[$1]++} END{for(k in c) print c[k], k}' | sort -rn | head -n 15
    break
  fi
done

echo "@@martians"
{ rjournalctl -k --since "-\${LB}min" --no-pager -o cat 2>/dev/null || rdmesg 2>/dev/null; } | grep -ci martian
echo "@@sysctl"
cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo -
cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || echo -
echo "@@uid0"; awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null
echo "@@procs"; ps -eo pid=,user=,pcpu=,pmem=,comm= --sort=-pcpu 2>/dev/null | head -n 8
echo "@@suspicious"
rsh -c 'for p in /proc/[0-9]*; do e=$(readlink "$p/exe" 2>/dev/null) || continue; case "$e" in /tmp/*|/var/tmp/*|/dev/shm/*) echo "pid \${p#/proc/} runs from $e";; esac; done; true' 2>/dev/null | head -n 20
ps -eo pid=,comm= 2>/dev/null | grep -iE ' (xmrig|kdevtmpfsi|kinsing|minerd|cpuminer|xmr-stak|kthreaddk)$' | awk '{print "pid " $1 " looks like a crypto miner: " $2}'

echo "@@f2b"
if command -v fail2ban-client >/dev/null 2>&1; then
  echo installed
  if rfail2ban-client ping >/dev/null 2>&1; then
    echo ok
    for j in $(rfail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do
      echo "jail $j"
      rfail2ban-client status "$j" 2>/dev/null | grep -E 'Currently banned|Total banned|Banned IP list' | cut -c1-6000
    done
  else
    echo denied
  fi
else
  echo missing
fi

echo "@@gw"; ip route show default 2>/dev/null | awk '{print $3; exit}'
echo "@@neigh"; ip neigh show 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $1, $(i+1)}'
echo "@@reboot"; if [ -f /var/run/reboot-required ]; then echo yes; else echo no; fi
echo "@@end"
`;
}
