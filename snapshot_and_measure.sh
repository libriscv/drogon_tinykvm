#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DVM="./.build/dvm"
DVM_PORT="${1:-8080}"
#TENANT="${2:-deno}"
#SNAPSHOT_FILE="program/${TENANT}/${TENANT}.mem"
TENANT="${2:-test.com}"
SNAPSHOT_FILE="program/hello_world.mem"
DVM_LOG=$(mktemp)
BENCH_LOG_NO_DROP=$(mktemp)
BENCH_LOG_DROP=$(mktemp)
trap "rm -f $DVM_LOG $BENCH_LOG_NO_DROP $BENCH_LOG_DROP" EXIT

# --- Step 1: Remove old snapshot ---
if [ -f "$SNAPSHOT_FILE" ]; then
	echo "Removing old snapshot: $SNAPSHOT_FILE"
	rm "$SNAPSHOT_FILE"
fi

# --- Step 2: Start DVM in snapshot-mode reorder ---
echo "Starting DVM in snapshot-mode reorder..."
$DVM -c 1 --port "$DVM_PORT" --snapshot-mode reorder > "$DVM_LOG" 2>&1 &
DVM_PID=$!

# Wait for DVM to be ready (use /drogon to avoid triggering tenant init)
for i in $(seq 1 40); do
	if curl -s -o /dev/null http://127.0.0.1:$DVM_PORT/drogon 2>/dev/null; then
		break
	fi
	if ! kill -0 $DVM_PID 2>/dev/null; then
		echo "ERROR: DVM exited unexpectedly"
		cat "$DVM_LOG"
		exit 1
	fi
	sleep 0.025
done

# --- Step 3: Send probing request ---
echo "Sending probing request..."
curl -D - http://127.0.0.1:$DVM_PORT/ -H "Host: $TENANT"
echo ""

# --- Step 3b: Send a second request to trigger VM reset (which saves the snapshot) ---
echo "Sending second request to trigger snapshot save..."
curl -s -o /dev/null http://127.0.0.1:$DVM_PORT/ -H "Host: $TENANT"

# --- Step 4: Shut down DVM gracefully ---
echo "Stopping DVM..."
kill $DVM_PID
wait $DVM_PID 2>/dev/null || true

cat "$DVM_LOG"

if [ -f "$SNAPSHOT_FILE" ]; then
	echo "Snapshot created: $SNAPSHOT_FILE ($(stat -c%s "$SNAPSHOT_FILE") bytes)"
else
	echo "WARNING: Snapshot file was not created"
	exit 1
fi

# --- Step 5: Run benchmarks ---
run_benchmark() {
	local logfile="$1"
	$DVM --no-ephemeral --port "$DVM_PORT" -c 1 >> "$logfile" 2>&1 &
	local pid=$!
	sleep 0.025
	./measure "$DVM_PORT" "$TENANT"
	kill -9 $pid
	wait $pid 2>/dev/null || true
}

median() {
	printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END {if(NR%2==1) print a[(NR+1)/2]; else print (a[NR/2]+a[NR/2+1])/2}'
}

echo ""
echo "=== Benchmark WITHOUT drop_caches ==="
for i in $(seq 1 50); do
	run_benchmark "$BENCH_LOG_NO_DROP"
done

echo ""
echo "=== Benchmark WITH drop_caches ==="
for i in $(seq 1 50); do
	echo 1 | sudo tee /proc/sys/vm/drop_caches > /dev/null
	run_benchmark "$BENCH_LOG_DROP"
done

echo ""
echo "=== Ready times (self-reported by DVM) ==="

readarray -t TIMES_NO_DROP < <(grep -oP "ready=\K[0-9.]+" "$BENCH_LOG_NO_DROP")
readarray -t TIMES_DROP < <(grep -oP "ready=\K[0-9.]+" "$BENCH_LOG_DROP")

if [ ${#TIMES_NO_DROP[@]} -gt 0 ]; then
	echo "Without drop_caches: median=$(median "${TIMES_NO_DROP[@]}")ms (n=${#TIMES_NO_DROP[@]})"
else
	echo "Without drop_caches: no ready times found"
	echo "Log contents:"
	cat "$BENCH_LOG_NO_DROP"
fi
if [ ${#TIMES_DROP[@]} -gt 0 ]; then
	echo "With drop_caches:    median=$(median "${TIMES_DROP[@]}")ms (n=${#TIMES_DROP[@]})"
else
	echo "With drop_caches: no ready times found"
	echo "Log contents:"
	cat "$BENCH_LOG_DROP"
fi
