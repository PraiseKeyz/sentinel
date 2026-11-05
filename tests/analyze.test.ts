import assert from 'node:assert/strict';
import { test } from 'node:test';
import { analyze, score, stateFor } from '../electron/analyze';
import { parseMetrics } from '../electron/parse';
import { parseSshConfig } from '../electron/sshconfig';
import { DEFAULT_SETTINGS } from '../shared/types';

const SAMPLE = `@@sudo
yes
@@client
41.58.10.2
@@host
web-01
Linux 6.8.0-45-generic
up 3 weeks, 2 days
@@cpus
2
@@load
4.10 2.00 1.50 3/412 9921
@@mem
MemTotal:        4000000 kB
MemAvailable:    1000000 kB
SwapTotal:       1000000 kB
SwapFree:         900000 kB
@@disk
/dev/vda1 41152736 38500000 2652736 94% /
/dev/vdb1 10000000 1000000 9000000 10% /data store
@@tcp
640
300
@@conns
   410 203.0.113.9
     3 41.58.10.2
@@listen
tcp 0.0.0.0:22 users:(("sshd",pid=812,fd=3))
tcp *:443 users:(("nginx",pid=900,fd=6))
@@failed
     52 198.51.100.23
      4 192.0.2.5
      9 not-an-ip
@@accepted
deploy 41.58.10.2 publickey
root 198.51.100.77 password
@@http
/var/log/nginx/access.log
  5200 203.0.113.50
   300 192.0.2.10
@@martians
12
@@sysctl
0
1
@@uid0
root
toor
@@procs
 1234 www-data 180.0 2.1 xmrig
  812 root 0.1 0.2 sshd
@@suspicious
pid 1234 runs from /tmp/.x/xmrig
@@f2b
installed
ok
jail sshd
   |- Currently banned:	2
   |- Total banned:	40
   \`- Banned IP list:	192.0.2.99 192.0.2.98
@@gw
10.0.0.1
@@neigh
10.0.0.1 aa:bb:cc:dd:ee:02
10.0.0.7 aa:bb:cc:dd:ee:02
@@reboot
yes
@@end
`;

test('parses collector output', () => {
  const m = parseMetrics(SAMPLE);
  assert.equal(m.hostname, 'web-01');
  assert.equal(m.uptime, '3 weeks, 2 days');
  assert.equal(m.cpus, 2);
  assert.deepEqual(m.load, [4.1, 2, 1.5]);
  assert.equal(m.memTotal, 4000000 * 1024);
  assert.equal(m.memUsed, 3000000 * 1024);
  assert.equal(m.disks[1].mount, '/data store');
  assert.equal(m.tcpEstablished, 640);
  assert.equal(m.synRecv, 300);
  assert.deepEqual(m.topConnIps[0], { ip: '203.0.113.9', count: 410 });
  assert.equal(m.failedLoginIps.length, 2, 'drops non-IP lines');
  assert.equal(m.listening[1].process, 'nginx');
  assert.equal(m.httpLogPath, '/var/log/nginx/access.log');
  assert.equal(m.httpTopIps[0].count, 5200);
  assert.equal(m.rpFilter, 0);
  assert.equal(m.syncookies, 1);
  assert.deepEqual(m.fail2ban.jails[0], { name: 'sshd', currentlyBanned: 2, totalBanned: 40, bannedIps: ['192.0.2.99', '192.0.2.98'] });
  assert.equal(m.gatewayMac, 'aa:bb:cc:dd:ee:02');
  assert.equal(m.clientIp, '41.58.10.2');
  assert.equal(m.sudo, true);
});

test('rejects truncated output', () => {
  assert.throws(() => parseMetrics(SAMPLE.replace('@@end', '')), /cut off/);
});

test('raises the expected findings', () => {
  const m = parseMetrics(SAMPLE);
  const findings = analyze(m, {
    settings: DEFAULT_SETTINGS,
    previousGatewayMac: 'aa:bb:cc:dd:ee:01',
    isProtected: (ip) => ip === '41.58.10.2',
  });
  const ids = findings.map((f) => f.id);
  for (const id of [
    'health:load',
    'health:disk:/',
    'health:reboot',
    'bruteforce:198.51.100.23',
    'intrusion:rootpw:198.51.100.77',
    'dos:synflood',
    'dos:conn:203.0.113.9',
    'dos:http:203.0.113.50',
    'spoofing:martians',
    'hardening:rpfilter',
    'spoofing:gwmac',
    'spoofing:arp:aa:bb:cc:dd:ee:02',
    'intrusion:uid0',
    'intrusion:proc:pid 1234 runs from /tmp/.x/xmrig',
  ]) {
    assert.ok(ids.includes(id), `missing ${id}`);
  }
  assert.ok(!ids.includes('bruteforce:192.0.2.5'), 'below threshold');
  assert.equal(findings.find((f) => f.id === 'bruteforce:198.51.100.23')?.bannable, true);
  assert.equal(findings[0].severity, 'critical', 'sorted by severity');
  assert.equal(stateFor(findings), 'critical');
  assert.equal(score(findings), 0);
});

test('never marks protected IPs as bannable', () => {
  const m = parseMetrics(SAMPLE);
  const findings = analyze(m, { settings: DEFAULT_SETTINGS, previousGatewayMac: null, isProtected: () => true });
  assert.ok(findings.every((f) => !f.bannable));
});

test('healthy server has no findings', () => {
  const quiet = SAMPLE.replace(/@@load\n.*\n/, '@@load\n0.10 0.1 0.1 1/1 1\n')
    .replace(/@@disk\n[\s\S]*?@@tcp/, '@@disk\n/dev/vda1 100 10 90 10% /\n@@tcp')
    .replace(/@@tcp\n640\n300/, '@@tcp\n4\n0')
    .replace(/@@conns[\s\S]*?@@listen/, '@@conns\n@@listen')
    .replace(/@@failed[\s\S]*?@@martians\n12/, '@@failed\n@@accepted\n@@http\n@@martians\n0')
    .replace(/@@sysctl\n0/, '@@sysctl\n1')
    .replace('toor\n', '')
    .replace(/@@suspicious\n.*\n/, '@@suspicious\n')
    .replace(/@@neigh[\s\S]*?@@reboot\nyes/, '@@neigh\n@@reboot\nno')
    .replace('MemAvailable:    1000000', 'MemAvailable:    3000000');
  const m = parseMetrics(quiet);
  const findings = analyze(m, { settings: DEFAULT_SETTINGS, previousGatewayMac: null, isProtected: () => false });
  assert.deepEqual(findings, []);
  assert.equal(stateFor(findings), 'healthy');
});

test('parses ssh config hosts', () => {
  const hosts = parseSshConfig(`
Host *
  ServerAliveInterval 30
Host prod web
  HostName 203.0.113.4
  User deploy
  Port 2222
  IdentityFile ~/.ssh/id_ed25519
Host github.com
  User git
`);
  assert.deepEqual(hosts.map((h) => h.alias), ['prod', 'web', 'github.com']);
  assert.deepEqual(hosts[0], { alias: 'prod', host: '203.0.113.4', port: 2222, username: 'deploy', keyPath: '~/.ssh/id_ed25519' });
});
