#!/usr/bin/env bash
# Usage: fapi.sh <curl args...>   (paths relative to $BASE, token kept in memory only)
BASE=https://api.us-2.crowdstrike.com
TOKEN=$(curl -s -X POST "$BASE/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$FALCON_CLIENT_ID&client_secret=$FALCON_CLIENT_SECRET" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])') || exit 1
path=$1; shift
curl -s -w '\nHTTP %{http_code}\n' -H "Authorization: Bearer $TOKEN" "$BASE$path" "$@"
