#!/bin/sh
# Cross-check the CLI signer (tools/tapout, ECDSA P-256 via openssl) against the
# device verifier and topic-URL guards (tapout/cmd_proto.h) on the host. The host
# build of cmd_proto.h verifies with OpenSSL (macOS: brew install openssl@3).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

if [ "$(uname)" = "Darwin" ]; then
  ossl="$(brew --prefix openssl@3 2>/dev/null || echo /opt/homebrew/opt/openssl@3)"
  c++ -std=c++17 -Wall -Wextra -I"$ossl/include" -o "$tmp/t" "$here/test_cmd_proto.cpp" -L"$ossl/lib" -lcrypto
else
  c++ -std=c++17 -Wall -Wextra -o "$tmp/t" "$here/test_cmd_proto.cpp" -lcrypto
fi

# Operator key pair (what `tapout init` makes) + an unrelated attacker key pair.
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/k.pem"
openssl ec -in "$tmp/k.pem" -pubout -out "$tmp/pub.pem" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/other.pem"
openssl ec -in "$tmp/other.pem" -pubout -out "$tmp/otherpub.pem" 2>/dev/null
printf -- '-----BEGIN PUBLIC KEY-----\nCHANGE-ME\n-----END PUBLIC KEY-----\n' > "$tmp/placeholder.pem"
# A P-384 key pair: the device must refuse it as a command key (P-256 only).
openssl ecparam -name secp384r1 -genkey -noout -out "$tmp/p384.pem"
openssl ec -in "$tmp/p384.pem" -pubout -out "$tmp/p384pub.pem" 2>/dev/null
PUB="$tmp/pub.pem"; OTHERPUB="$tmp/otherpub.pem"

export TAPOUT_CONFIG="$tmp/none.json" TAPOUT_CMD_URL="https://ntfy.sh/unused" \
       TAPOUT_STATUS_URL="https://ntfy.sh/unused-status" TAPOUT_CMD_PRIVATE_KEY="$tmp/k.pem"
cli() { python3 "$here/tapout" --dry-run --yes "$@" 2>/dev/null; }
# Sign an arbitrary pre-built line with the operator key (for inputs the CLI refuses to produce).
rawsign() {
  sig="$(printf '%s' "$1" | openssl dgst -sha256 -sign "$tmp/k.pem" | python3 -c 'import base64,sys;print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip("="))')"
  printf '%s;sig=%s\n' "$1" "$sig"
}
CREW=https://ntfy.sh/pcfd-crew-alerts

{
  # --- signer <-> verifier round trips
  echo "OK $PUB $(cli ping)"
  echo "OK $PUB $(cli test -m 'Hello; crew = 100% "quoted" \back ✓')"
  echo "OK $PUB $(cli maint start --minutes 45 -m 'Swapping the ELK-930')"
  echo "OK $PUB $(cli sim-ring --to call)"                                   # the only crew-bound command
  echo "OK $PUB $(cli maint end)"
  echo "OK $PUB $(cli announce -t 'Line work' -m 'Tue 0900-1000' -p high)"
  echo "OK $PUB $(cli send -t 'Heads up' -m 'Custom text; any 100% chars' --url other-topic)"
  echo "OK $PUB $(cli test --url https://ntfy.sh/some-other-topic)"
  echo "OK $PUB $(cli set-topic call https://NTFY.sh/new-crew-topic)"
  echo "OK $PUB $(cli revert-topic status)"
  echo "OK $PUB $(cli confirm-topic call --code a1b2c3)"
  echo "OK $PUB $(cli ring-mode pattern)"
  echo "OK $PUB $(cli ring-mode single --min-ms 800)"
  echo "OK $PUB $(cli sim-ring)"
  echo "OK $PUB $(cli reboot)"
  # --- forgery / tampering
  echo "BAD_SIG $OTHERPUB $(cli ping)"                                       # signed by a different key
  echo "BAD_SIG $PUB $(cli test | sed 's/to=status/to=call/')"    # re-route to crew
  echo "BAD_SIG $PUB $(cli maint start --minutes 5 | sed 's/m=5/m=500/')"     # tamper field
  echo "BAD_SIG $PUB $(cli test --url https://ntfy.sh/aaaa | sed 's/aaaa/bbbb/')"  # swap target URL
  echo "BAD_SIG $PUB $(cli ring-mode single | sed 's/w=single/w=pattern/')"   # flip ring mode
  echo "NO_SIG $PUB $(cli ping | sed 's/;sig=.*//')"                         # stripped signature
  echo "NO_SIG $PUB $(cli ping | sed 's/;sig=.*/;sig=/')"                    # empty signature
  echo "FORMAT $PUB T1;ts=1;id=aa;c=ping;sig=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"  # old HMAC format
  echo "FORMAT $PUB hello world"
  echo "NO_KEY $tmp/placeholder.pem $(cli ping)"                             # placeholder public key
  echo "NO_KEY $tmp/p384pub.pem $(cli ping)"                                 # device key on the wrong curve (P-384): refused
  echo "NO_SIG $PUB $(TAPOUT_CMD_PRIVATE_KEY=$tmp/p384.pem cli ping)"        # P-384 signature: too long to even be a P-256 sig
  # --- header injection: a newline in the title (becomes the Title: header) must be
  #     rejected even when correctly signed; a newline in the body is fine.
  echo "TOO_LONG $PUB $(rawsign 'T2;ts=1;id=aa;c=announce;to=call;p=high;ti=Hi%0APriority%3A%20max;b=x')"
  echo "TOO_LONG $PUB $(rawsign 'T2;ts=1;id=aa;c=test;to=url;u=https%3A%2F%2Fntfy.sh%2Fx%0Ay')"
  echo "OK $PUB $(rawsign 'T2;ts=1;id=aa;c=announce;b=line1%0Aline2')"
  # --- strict URL shape (device side)
  echo "URL ok https://ntfy.sh/pcfd-status_2"
  echo "URL ok https://NTFY.sh/Mixed-Case"
  echo "URL bad https://ntfy.sh/crew?priority=max"
  echo "URL bad https://ntfy.sh/crew#x"
  echo "URL bad https://ntfy.sh/crew/"
  echo "URL bad https://ntfy.sh:443/crew"
  echo "URL bad https://user@ntfy.sh/crew"
  echo "URL bad https://ntfy.sh/a/b"
  echo "URL bad http://ntfy.sh/crew"
  echo "URL bad https://localhost/crew"
  # --- same-topic guard: every spelling ntfy treats as the crew topic must match
  echo "SAME yes $CREW https://NTFY.SH/pcfd-crew-alerts"
  echo "SAME yes $CREW https://ntfy.sh/pcfd-crew-alerts?priority=max"
  echo "SAME yes $CREW https://ntfy.sh/pcfd-crew-alerts/"
  echo "SAME yes $CREW https://ntfy.sh:443/pcfd-crew-alerts#frag"
  echo "SAME yes $CREW https://ntfy.sh/PCFD-CREW-ALERTS"
  echo "SAME no $CREW https://ntfy.sh/pcfd-crew-alerts2"
  echo "SAME yes $CREW https://159.203.148.75/pcfd-crew-alerts"      # same server by IP
  echo "SAME yes $CREW https://ntfy.sh./pcfd-crew-alerts"             # trailing-dot FQDN
  echo "SAME yes $CREW https://www.ntfy.sh/pcfd-crew-alerts"          # alias host
  echo "SAME yes $CREW https://ntfy.example.org/pcfd-crew-alerts"     # same name elsewhere: refused too (conservative)
  echo "SAME no $CREW https://ntfy.sh/pcfd-status"
} > "$tmp/cases"

# The CLI must refuse these outright (exit != 0, nothing printed).
refuse() {
  if python3 "$here/tapout" --dry-run --yes "$@" >/dev/null 2>&1; then echo "FAIL  cli accepted: $*"; exit 1; fi
  echo "PASS  cli refuses: $*" | tr '\n' ' '; echo
}
refuse announce -t "$(printf 'Hi\nPriority: max')" -m x
refuse test --url 'https://ntfy.sh/x?y=1'
refuse test --url 'https://ntfy.sh:443/x'
refuse test --url 'https://ntfy.sh/x/'
refuse test --to call --url other-topic
refuse test --to call                                                       # crew channel = standard alert only
refuse send -m hi --to call
refuse maint start --to call
refuse ring-mode single --min-ms 50
refuse ring-mode single --min-ms 2000
refuse ring-mode
( TAPOUT_CMD_PRIVATE_KEY="$tmp/missing.pem"; refuse ping )                  # no private key (subshell: sh keeps VAR=x func assignments)
python3 "$here/tapout" --dry-run --yes announce -t 'Fine title' -m x >/dev/null   # control: accepted

"$tmp/t" < "$tmp/cases"
