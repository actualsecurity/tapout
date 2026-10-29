// ECDSA P-256 PUBLIC key that verifies remote commands (tools/tapout). Committed,
// not secret -- the matching PRIVATE key lives only on the operator's machine
// (~/.config/tapout/cmd_private_key.pem) and never in this repo.
//
// PLACEHOLDER: while this still says CHANGE-ME the command channel stays OFF
// (fail closed), exactly like public_key.h gates OTA. Generate a real key with
//   tools/tapout init --status-url https://ntfy.sh/<status-topic>
// which rewrites this file; commit it and cut a release to enable commands.
#pragma once
static const char CMD_PUBLIC_KEY[] =
  "-----BEGIN PUBLIC KEY-----\n"
  "CHANGE-ME\n"
  "-----END PUBLIC KEY-----\n";
