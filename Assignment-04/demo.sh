#!/bin/bash
# Verification walkthrough. Start the matching app first, then run from this folder:
#   node app.vulnerable.js   ->  ./demo.sh vulnerable
#   node app.js              ->  ./demo.sh secure
# Run with PAUSE=1 to stop between sections and press Enter, so each fits in one screenshot.
trap 'rm -f cookies.txt' EXIT

run() { printf '+ %s\n' "$1"; eval "$1"; }
title() { printf '=== %s ===\n' "$1"; }
pause() { if [ -n "$PAUSE" ]; then read -r; clear; fi; }

vulnerable() {
  local URL=http://localhost:3000
  title "Vulnerable build: forged POST with session cookie and no token"
  run "curl -si -c cookies.txt $URL/account -w '\n'"
  run "curl -si -b cookies.txt -H 'Origin: http://localhost:4000' -d 'email=attacker@evil.com' $URL/account/email -w '\n'"
  run "curl -s -b cookies.txt $URL/account | grep 'Current email'"
}

secure() {
  local URL=https://localhost:3000
  title "Secure build: cookie attributes and embedded token"
  run "curl -ski -c cookies.txt $URL/account -w '\n'"
  pause

  title "Secure build: forged requests"
  run "curl -ski -b cookies.txt -H 'Origin: https://localhost:4000' -d 'email=attacker@evil.com' $URL/account/email -w '\n'"
  run "curl -sk -o /dev/null -w 'wrong token: HTTP %{http_code}\n' -b cookies.txt -d '_csrf=deadbeef&email=attacker@evil.com' $URL/account/email"
  run "curl -sk -o /dev/null -w 'PUT no token: HTTP %{http_code}\n' -b cookies.txt -X PUT -d 'email=attacker@evil.com' $URL/account/email"
  run "curl -sk -o /dev/null -w 'DELETE no token: HTTP %{http_code}\n' -b cookies.txt -X DELETE $URL/account/email"
  run "curl -sk -b cookies.txt $URL/account | grep 'Current email'"
  pause

  title "Secure build: legitimate requests with the session token"
  TOKEN=$(curl -sk -b cookies.txt "$URL/account" | grep -oP 'name="_csrf" value="\K[^"]+')
  run 'echo $TOKEN'
  run "curl -sk -b cookies.txt -d \"_csrf=\$TOKEN&email=tashi.new@example.com\" $URL/account/email -w ' [HTTP %{http_code}]\n'"
  run "curl -sk -b cookies.txt -X PUT -H \"X-CSRF-Token: \$TOKEN\" -d 'email=tashi.put@example.com' $URL/account/email -w ' [HTTP %{http_code}]\n'"
  run "curl -sk -b cookies.txt -X DELETE -H \"X-CSRF-Token: \$TOKEN\" $URL/account/email -w ' [HTTP %{http_code}]\n'"
  run "curl -sk -b cookies.txt $URL/account | grep 'Current email'"
}

case "$1" in
  vulnerable) vulnerable ;;
  secure) secure ;;
  *) echo "usage: ./demo.sh <vulnerable|secure>"; exit 1 ;;
esac
