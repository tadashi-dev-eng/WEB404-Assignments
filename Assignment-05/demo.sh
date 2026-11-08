#!/bin/bash
# Verification walkthrough. Start the app first with: node app.js
# Run from this folder with: ./demo.sh
URL=https://localhost:3000
PASSWORD="${DEMO_PASSWORD:-lab-password-only}"
trap 'rm -f cookies.txt' EXIT

title() { printf '\n=== %s ===\n' "$1"; }
token() { awk '$6 == "token" { print $7 }' cookies.txt; }
status() { curl -sk -o /dev/null -w "$1: HTTP %{http_code}\n" "${@:2}"; }

title "No token"
status "GET /api/profile with no cookie" "$URL/api/profile"

title "Wrong password"
status "POST /login with wrong password" -H 'Content-Type: application/json' \
  -d '{"username":"tashi","password":"wrong"}' "$URL/login"

title "Login and cookie attributes"
curl -ski -c cookies.txt -H 'Content-Type: application/json' \
  -d "{\"username\":\"tashi\",\"password\":\"$PASSWORD\"}" "$URL/login" \
  | grep -iE '^HTTP|^set-cookie' | sed -E 's/(token=.{24})[^;]*/\1.../'

title "Decoded token header and claims"
token | cut -d. -f1 | node -e 'console.log(Buffer.from(require("fs").readFileSync(0,"utf8").trim(),"base64url").toString())'
token | cut -d. -f2 | node -e 'const c=JSON.parse(Buffer.from(require("fs").readFileSync(0,"utf8").trim(),"base64url"));console.log(c);console.log("lifetime seconds:",c.exp-c.iat)'

# Run with PAUSE=1 to stop here and press Enter, so each half fits in one screenshot
if [ -n "$PAUSE" ]; then read -r; clear; fi

title "Valid token on protected routes"
curl -sk -b cookies.txt -w ' [HTTP %{http_code}]\n' "$URL/api/profile"
status "GET /api/admin as role=user" -b cookies.txt "$URL/api/admin"

title "Invalid tokens on GET /api/profile"
for kind in expired wrong-issuer wrong-audience wrong-key tampered none hs256; do
  status "$kind" --cookie "token=$(node make-token.js "$kind")" "$URL/api/profile"
done

title "Logout"
status "POST /logout" -b cookies.txt -c cookies.txt -X POST "$URL/logout"
status "GET /api/profile after logout" -b cookies.txt "$URL/api/profile"
