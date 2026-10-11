#!/bin/sh
# Frozen P1-MCP-01 lane child: replays a pinned signed-current response byte stream.
[ "$1" = "current-query" ] || exit 9
[ "$PATH" = "/usr/bin:/bin" ] || exit 13
shift
store=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --store)
      shift
      store=$1
      ;;
    --candidate | --candidate-sha256) exit 12 ;;
  esac
  shift
done
[ -n "$store" ] || exit 10
# A block marker simulates a wedged lane; the broker's fixed lane deadline must reap it.
if [ -e "$store/block" ]; then
  sleep 600
fi
cat "$store/response.json"
