#!/usr/bin/env bash
# Runs chaos tests and prints a banner with metrics (matching mutation/unit/integration test style).
set -euo pipefail

# ANSI color codes
ESC=$(printf '\033')
COLOR_RESET="${ESC}[0m"
COLOR_RED="${ESC}[31m"
COLOR_GREEN="${ESC}[32m"
COLOR_YELLOW="${ESC}[33m"
COLOR_CYAN="${ESC}[36m"
COLOR_BLUE="${ESC}[34m"
COLOR_BOLD="${ESC}[1m"
COLOR_WHITE="${ESC}[97m"
GREEN_BRIGHT="${ESC}[92m"
RED_BOLD="${ESC}[31;1m"

# Chaos test configuration (passed from GitLab CI variables)
ASSAULT_TYPE="${ASSAULT_TYPE:-latency}"
ASSAULT_DURATION="${ASSAULT_DURATION:-60}"
LATENCY_MIN="${LATENCY_MIN:-1000}"
LATENCY_MAX="${LATENCY_MAX:-3000}"
BASE_URL="${BASE_URL:-}"
CI_ENVIRONMENT_NAME="${CI_ENVIRONMENT_NAME:-test}"
CI_COMMIT_SHA="${CI_COMMIT_SHA:-unknown}"

# Output directory
CHAOS_DIR="tests/chaos"
mkdir -p "$CHAOS_DIR"

# Artifact URL configuration (matching mutation test approach)
CHAOS_ARTIFACT_URL_MODE="${CHAOS_ARTIFACT_URL_MODE:-auto}"
CHAOS_ARTIFACT_URL_BASE="${CHAOS_ARTIFACT_URL_BASE:-}"
CHAOS_HOST_PREFIX="${CHAOS_HOST_PREFIX:-enterprise-interactions-platform}"
CHAOS_GROUP_PATH_OVERRIDE="${CHAOS_GROUP_PATH_OVERRIDE:--}"

# Helper function to strip ANSI codes for width calculation
_strip_ansi() { sed -E 's/\x1B\[[0-9;]*m//g; s/\x1B]8;;[^\x1B]*\x1B\\//g; s/\x1B]8;;[^\x07]*\x07//g'; }

# Build artifact URL - matching pattern from unit/mutation test scripts
build_artifact_url() {
  local rel="$1"
  [ -z "$rel" ] && { printf '%s' ""; return 0; }
  local mode="$CHAOS_ARTIFACT_URL_MODE"
  if [ "$mode" = "auto" ]; then
    mode="file"
  fi
  local base_override="$CHAOS_ARTIFACT_URL_BASE"
  local url=""
  if [ -n "$base_override" ]; then
    base_override="${base_override%/}"
    url="${base_override}/${rel}"
  else
    local derived_project_url="${CI_PROJECT_URL:-}"
    if [ -n "$CHAOS_HOST_PREFIX" ] && [ -n "${CI_SERVER_HOST:-}" ]; then
      if [ -n "$derived_project_url" ]; then
        local host_part="$(printf '%s' "$derived_project_url" | sed -E 's|https?://([^/]+)/.*|\1|')"
        local rest="$(printf '%s' "$derived_project_url" | sed -E 's|https?://[^/]+/(.*)|\1|')"
        derived_project_url="https://${CHAOS_HOST_PREFIX}.${CI_SERVER_HOST}/${rest}"
      else
        derived_project_url="https://${CHAOS_HOST_PREFIX}.${CI_SERVER_HOST}/${CHAOS_GROUP_PATH_OVERRIDE:+$CHAOS_GROUP_PATH_OVERRIDE/}${CI_PROJECT_NAME:-}"
      fi
    fi
    if [ -n "$CHAOS_GROUP_PATH_OVERRIDE" ] && [ -n "$derived_project_url" ]; then
      local proto_host="$(printf '%s' "$derived_project_url" | sed -E 's|(https?://[^/]+)/.*|\1|')"
      local proj="${CI_PROJECT_NAME:-$(printf '%s' "$derived_project_url" | sed -E 's|.*/([^/]+)/?$|\1|')}"
      derived_project_url="${proto_host}/${CHAOS_GROUP_PATH_OVERRIDE}/${proj}"
    fi
    if [ "$mode" = "direct" ] || [ "$mode" = "file" ]; then
      if [ -n "${CI_JOB_ID:-}" ] && [ -n "$derived_project_url" ]; then
        url="${derived_project_url}/-/jobs/${CI_JOB_ID}/artifacts/${rel}"
      fi
    fi
  fi
  printf '%s' "$url"
}

# Validate required parameters
if [ -z "$BASE_URL" ]; then
  echo "${COLOR_RED}[ERROR] BASE_URL is not set. Cannot run chaos tests.${COLOR_RESET}" >&2
  exit 1
fi

# Wait for correct commit to be deployed (silent)
EXPECTED_COMMIT_SHORT="${CI_COMMIT_SHA:0:7}"

for i in {1..30}; do
  HEALTH_RAW=$(curl -s -m 5 "$BASE_URL/health" 2>/dev/null || true)
  if [[ -n "$HEALTH_RAW" ]]; then
    ACTUAL_COMMIT_FULL=$(echo "$HEALTH_RAW" | sed -n 's/.*"gitCommitId"[[:space:]]*:[[:space:]]*"\([0-9a-fA-F]\{7,40\}\)".*/\1/p' | head -n1)
    ACTUAL_COMMIT=${ACTUAL_COMMIT_FULL:0:7}
    if [[ -n "$ACTUAL_COMMIT" && "$ACTUAL_COMMIT" == "$EXPECTED_COMMIT_SHORT" ]]; then
      break
    fi
  fi
  sleep 10
done

if [[ -z "${ACTUAL_COMMIT:-}" || "$ACTUAL_COMMIT" != "$EXPECTED_COMMIT_SHORT" ]]; then
  echo "${COLOR_RED}[ERROR] Timed out waiting for commit $EXPECTED_COMMIT_SHORT to be deployed!${COLOR_RESET}" >&2
  exit 1
fi

# Verify application health (silent)
HEALTH_STATUS=$(curl -s -m 5 "$BASE_URL/actuator/health" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
if [[ "$HEALTH_STATUS" != "UP" ]]; then
  echo "${COLOR_RED}[ERROR] Application is not healthy. Status: $HEALTH_STATUS${COLOR_RESET}" >&2
  exit 1
fi

# Phase 1: Baseline Performance Measurement (silent)

echo "timestamp_ms,response_time_ms,http_code,phase" > "$CHAOS_DIR/latency-metrics.csv"

BASELINE_START=$(date +%s)
BASELINE_SAMPLES=0
BASELINE_TOTAL=0
BASELINE_MAX=0
BASELINE_ERRORS=0

while [ $(($(date +%s) - BASELINE_START)) -lt 30 ]; do
  START_MS=$(date +%s%3N)
  RESPONSE=$(curl -s -w "\n%{http_code}\n%{time_total}" -m 5 "$BASE_URL/actuator/health" 2>/dev/null || echo -e "\n000\n5.000")
  END_MS=$(date +%s%3N)
  
  HTTP_CODE=$(echo "$RESPONSE" | sed -n '2p')
  TIME_TOTAL=$(echo "$RESPONSE" | sed -n '3p')
  RESPONSE_TIME_MS=$(awk "BEGIN {print int($TIME_TOTAL * 1000)}")
  
  echo "$END_MS,$RESPONSE_TIME_MS,$HTTP_CODE,baseline" >> "$CHAOS_DIR/latency-metrics.csv"
  
  if [ "$HTTP_CODE" = "200" ]; then
    BASELINE_SAMPLES=$((BASELINE_SAMPLES + 1))
    BASELINE_TOTAL=$((BASELINE_TOTAL + RESPONSE_TIME_MS))
    [ $RESPONSE_TIME_MS -gt $BASELINE_MAX ] && BASELINE_MAX=$RESPONSE_TIME_MS
  else
    BASELINE_ERRORS=$((BASELINE_ERRORS + 1))
  fi
  
  sleep 1
done

BASELINE_AVG=$((BASELINE_TOTAL / (BASELINE_SAMPLES > 0 ? BASELINE_SAMPLES : 1)))
BASELINE_ERROR_RATE=$(awk "BEGIN {printf \"%.2f\", ($BASELINE_ERRORS / ($BASELINE_SAMPLES + $BASELINE_ERRORS)) * 100}")

# Phase 2: Chaos Injection (silent)

ENABLE_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/actuator/chaosmonkey/enable" 2>/dev/null || echo -e "\n000")
HTTP_CODE=$(echo "$ENABLE_RESPONSE" | tail -n1)
ENABLE_BODY=$(echo "$ENABLE_RESPONSE" | head -n-1)

if [[ "$HTTP_CODE" != "200" ]] || echo "$ENABLE_BODY" | grep -q "error"; then
  echo "${COLOR_RED}[ERROR] Failed to enable Chaos Monkey (HTTP $HTTP_CODE): $ENABLE_BODY${COLOR_RESET}" >&2
  exit 1
fi

# Configure assault (silent)
if [[ "$ASSAULT_TYPE" == "latency" ]]; then
  ASSAULT_CONFIG="{\"level\":1,\"latencyRangeStart\":$LATENCY_MIN,\"latencyRangeEnd\":$LATENCY_MAX,\"latencyActive\":true,\"exceptionsActive\":false,\"killApplicationActive\":false,\"memoryActive\":false}"
elif [[ "$ASSAULT_TYPE" == "memory" ]]; then
  ASSAULT_CONFIG='{"level":1,"latencyActive":false,"exceptionsActive":false,"killApplicationActive":false,"memoryActive":true,"memoryMillisecondsHoldFilledMemory":90000,"memoryMillisecondsWaitNextIncrease":1000,"memoryFillIncrementFraction":0.15,"memoryFillTargetFraction":0.25}'
elif [[ "$ASSAULT_TYPE" == "exception" ]]; then
  ASSAULT_CONFIG='{"level":1,"latencyActive":false,"exceptionsActive":true,"exception":{"type":"java.lang.RuntimeException","arguments":[{"className":"java.lang.String","value":"Chaos Monkey Exception"}]},"killApplicationActive":false,"memoryActive":false}'
else
  ASSAULT_CONFIG="{\"level\":1,\"latencyRangeStart\":1000,\"latencyRangeEnd\":3000,\"latencyActive\":true,\"exceptionsActive\":false,\"killApplicationActive\":false,\"memoryActive\":false}"
fi

ASSAULT_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/actuator/chaosmonkey/assaults" -H "Content-Type: application/json" -d "$ASSAULT_CONFIG" 2>/dev/null || echo -e "\n000")
HTTP_CODE=$(echo "$ASSAULT_RESPONSE" | tail -n1)

if [[ "$HTTP_CODE" != "200" ]]; then
  echo "${COLOR_RED}[ERROR] Failed to configure assault (HTTP $HTTP_CODE)${COLOR_RESET}" >&2
  exit 1
fi

# Measure impact during chaos (silent)

CHAOS_START=$(date +%s)
CHAOS_SAMPLES=0
CHAOS_TOTAL=0
CHAOS_MAX=0
CHAOS_ERRORS=0
CHAOS_TIMEOUT=0

while [ $(($(date +%s) - CHAOS_START)) -lt $ASSAULT_DURATION ]; do
  START_MS=$(date +%s%3N)
  RESPONSE=$(curl -s -w "\n%{http_code}\n%{time_total}" -m 5 "$BASE_URL/actuator/health" 2>&1)
  CURL_EXIT=$?
  END_MS=$(date +%s%3N)
  
  if [ $CURL_EXIT -eq 28 ]; then
    echo "$END_MS,5000,timeout,chaos" >> "$CHAOS_DIR/latency-metrics.csv"
    CHAOS_TIMEOUT=$((CHAOS_TIMEOUT + 1))
  else
    HTTP_CODE=$(echo "$RESPONSE" | sed -n '2p')
    TIME_TOTAL=$(echo "$RESPONSE" | sed -n '3p')
    RESPONSE_TIME_MS=$(awk "BEGIN {print int($TIME_TOTAL * 1000)}")
    
    echo "$END_MS,$RESPONSE_TIME_MS,$HTTP_CODE,chaos" >> "$CHAOS_DIR/latency-metrics.csv"
    
    if [ "$HTTP_CODE" = "200" ]; then
      CHAOS_SAMPLES=$((CHAOS_SAMPLES + 1))
      CHAOS_TOTAL=$((CHAOS_TOTAL + RESPONSE_TIME_MS))
      [ $RESPONSE_TIME_MS -gt $CHAOS_MAX ] && CHAOS_MAX=$RESPONSE_TIME_MS
    else
      CHAOS_ERRORS=$((CHAOS_ERRORS + 1))
    fi
  fi
  
  sleep 1
done

CHAOS_AVG=$((CHAOS_TOTAL / (CHAOS_SAMPLES > 0 ? CHAOS_SAMPLES : 1)))
CHAOS_ERROR_RATE=$(awk "BEGIN {printf \"%.2f\", (($CHAOS_ERRORS + $CHAOS_TIMEOUT) / ($CHAOS_SAMPLES + $CHAOS_ERRORS + $CHAOS_TIMEOUT)) * 100}")
LATENCY_INCREASE=$(awk "BEGIN {printf \"%.1f\", (($CHAOS_AVG - $BASELINE_AVG) / ($BASELINE_AVG > 0 ? $BASELINE_AVG : 1)) * 100}")

# Phase 3: Recovery Verification (silent)

DISABLE_RESPONSE=$(curl -s -X POST "$BASE_URL/actuator/chaosmonkey/disable" 2>/dev/null || true)

RECOVERY_START=$(date +%s)
RECOVERY_SAMPLES=0
RECOVERY_TOTAL=0
RECOVERY_MAX=0
RECOVERY_ERRORS=0

while [ $(($(date +%s) - RECOVERY_START)) -lt 30 ]; do
  START_MS=$(date +%s%3N)
  RESPONSE=$(curl -s -w "\n%{http_code}\n%{time_total}" -m 5 "$BASE_URL/actuator/health" 2>/dev/null || echo -e "\n000\n5.000")
  END_MS=$(date +%s%3N)
  
  HTTP_CODE=$(echo "$RESPONSE" | sed -n '2p')
  TIME_TOTAL=$(echo "$RESPONSE" | sed -n '3p')
  RESPONSE_TIME_MS=$(awk "BEGIN {print int($TIME_TOTAL * 1000)}")
  
  echo "$END_MS,$RESPONSE_TIME_MS,$HTTP_CODE,recovery" >> "$CHAOS_DIR/latency-metrics.csv"
  
  if [ "$HTTP_CODE" = "200" ]; then
    RECOVERY_SAMPLES=$((RECOVERY_SAMPLES + 1))
    RECOVERY_TOTAL=$((RECOVERY_TOTAL + RESPONSE_TIME_MS))
    [ $RESPONSE_TIME_MS -gt $RECOVERY_MAX ] && RECOVERY_MAX=$RESPONSE_TIME_MS
  else
    RECOVERY_ERRORS=$((RECOVERY_ERRORS + 1))
  fi
  
  sleep 1
done

RECOVERY_AVG=$((RECOVERY_TOTAL / (RECOVERY_SAMPLES > 0 ? RECOVERY_SAMPLES : 1)))
RECOVERY_ERROR_RATE=$(awk "BEGIN {printf \"%.2f\", ($RECOVERY_ERRORS / ($RECOVERY_SAMPLES + $RECOVERY_ERRORS)) * 100}")
RECOVERY_DIFF=$(awk "BEGIN {printf \"%.1f\", (($RECOVERY_AVG - $BASELINE_AVG) / ($BASELINE_AVG > 0 ? $BASELINE_AVG : 1)) * 100}")

# Calculate resilience scores
LATENCY_SCORE=100
ERROR_SCORE=100
RECOVERY_SCORE=100

# Penalize if latency increased more than expected range
if [ $(awk "BEGIN {print ($CHAOS_AVG > $LATENCY_MAX)}") -eq 1 ]; then
  LATENCY_SCORE=$(awk "BEGIN {printf \"%.0f\", 100 - ((($CHAOS_AVG - $LATENCY_MAX) / ($LATENCY_MAX > 0 ? $LATENCY_MAX : 1)) * 50)}")
  [ $LATENCY_SCORE -lt 0 ] && LATENCY_SCORE=0
fi

# Penalize errors during chaos
if [ $(awk "BEGIN {print ($CHAOS_ERROR_RATE > 5)}") -eq 1 ]; then
  ERROR_SCORE=$(awk "BEGIN {printf \"%.0f\", 100 - ($CHAOS_ERROR_RATE * 2)}")
  [ $ERROR_SCORE -lt 0 ] && ERROR_SCORE=0
fi

# Penalize poor recovery
if [ $(awk "BEGIN {print ($RECOVERY_AVG > $BASELINE_AVG * 1.2)}") -eq 1 ]; then
  RECOVERY_SCORE=$(awk "BEGIN {printf \"%.0f\", 100 - ((($RECOVERY_AVG - $BASELINE_AVG) / ($BASELINE_AVG > 0 ? $BASELINE_AVG : 1)) * 100)}")
  [ $RECOVERY_SCORE -lt 0 ] && RECOVERY_SCORE=0
fi

OVERALL_SCORE=$(awk "BEGIN {printf \"%.0f\", ($LATENCY_SCORE + $ERROR_SCORE + $RECOVERY_SCORE) / 3}")

# Determine status and color
if [ $OVERALL_SCORE -ge 80 ]; then
  TEST_STATUS="EXCELLENT"
  BANNER_COLOR="$GREEN_BRIGHT"
elif [ $OVERALL_SCORE -ge 60 ]; then
  TEST_STATUS="GOOD"
  BANNER_COLOR="$COLOR_GREEN"
elif [ $OVERALL_SCORE -ge 40 ]; then
  TEST_STATUS="ACCEPTABLE"
  BANNER_COLOR="$COLOR_YELLOW"
else
  TEST_STATUS="NEEDS IMPROVEMENT"
  BANNER_COLOR="$RED_BOLD"
fi

# Build phase data with color coding
declare -a phase_rows
phase_rows=()

# Color code latency: green if <= expected max, yellow if <= 2x max, red otherwise
latency_color() {
  local avg=$1
  local expected_max=$2
  if [ $avg -le $expected_max ]; then
    echo "$COLOR_GREEN"
  elif [ $avg -le $((expected_max * 2)) ]; then
    echo "$COLOR_YELLOW"
  else
    echo "$COLOR_RED"
  fi
}

# Color code errors: green if 0, red if > 0
error_color() {
  local errors=$1
  if [ $errors -eq 0 ]; then
    echo "$COLOR_GREEN"
  else
    echo "$COLOR_RED"
  fi
}

# Color code error rate: green if < 1%, yellow if < 5%, red otherwise
error_rate_color() {
  local rate=$1
  if awk "BEGIN {exit !($rate < 1.0)}"; then
    echo "$COLOR_GREEN"
  elif awk "BEGIN {exit !($rate < 5.0)}"; then
    echo "$COLOR_YELLOW"
  else
    echo "$COLOR_RED"
  fi
}

# Build phase data rows
BASELINE_LAT_COLOR=$(latency_color $BASELINE_AVG 500)
BASELINE_ERR_COLOR=$(error_color $BASELINE_ERRORS)
BASELINE_RATE_COLOR=$(error_rate_color $BASELINE_ERROR_RATE)

CHAOS_LAT_COLOR=$(latency_color $CHAOS_AVG $LATENCY_MAX)
CHAOS_ERR_COLOR=$(error_color $((CHAOS_ERRORS + CHAOS_TIMEOUT)))
CHAOS_RATE_COLOR=$(error_rate_color $CHAOS_ERROR_RATE)

RECOVERY_LAT_COLOR=$(latency_color $RECOVERY_AVG $((BASELINE_AVG + BASELINE_AVG / 5)))
RECOVERY_ERR_COLOR=$(error_color $RECOVERY_ERRORS)
RECOVERY_RATE_COLOR=$(error_rate_color $RECOVERY_ERROR_RATE)

# Generate CSV and summary artifacts
CSV_ARTIFACT_URL=$(build_artifact_url "$CHAOS_DIR/latency-metrics.csv")
SUMMARY_ARTIFACT_URL=$(build_artifact_url "$CHAOS_DIR/chaos-test-summary.txt")

# Build formatted phase rows with color-coded values
phase_rows+=("Baseline|$BASELINE_SAMPLES|${BASELINE_LAT_COLOR}${BASELINE_AVG}ms${COLOR_RESET}|${BASELINE_LAT_COLOR}${BASELINE_MAX}ms${COLOR_RESET}|${BASELINE_ERR_COLOR}${BASELINE_ERRORS}${COLOR_RESET}|${BASELINE_RATE_COLOR}${BASELINE_ERROR_RATE}%${COLOR_RESET}")
phase_rows+=("Chaos|$CHAOS_SAMPLES|${CHAOS_LAT_COLOR}${CHAOS_AVG}ms (+${LATENCY_INCREASE}%)${COLOR_RESET}|${CHAOS_LAT_COLOR}${CHAOS_MAX}ms${COLOR_RESET}|${CHAOS_ERR_COLOR}$((CHAOS_ERRORS + CHAOS_TIMEOUT))${COLOR_RESET}|${CHAOS_RATE_COLOR}${CHAOS_ERROR_RATE}%${COLOR_RESET}")
phase_rows+=("Recovery|$RECOVERY_SAMPLES|${RECOVERY_LAT_COLOR}${RECOVERY_AVG}ms (${RECOVERY_DIFF}%)${COLOR_RESET}|${RECOVERY_LAT_COLOR}${RECOVERY_MAX}ms${COLOR_RESET}|${RECOVERY_ERR_COLOR}${RECOVERY_ERRORS}${COLOR_RESET}|${RECOVERY_RATE_COLOR}${RECOVERY_ERROR_RATE}%${COLOR_RESET}")

# Build all output lines first to calculate maximum width
output_lines=()
max_line_width=0

# Header line with proper column alignment
header_stats="                           Statistics:"
header_line=$(printf "%-15s %-100s %s" "Phase:" "Direct Link To Report:" "$header_stats")
output_lines+=("$header_line")
header_width=$(printf '%s' "$header_line" | _strip_ansi | wc -c | tr -d ' ')
[ "$header_width" -gt "$max_line_width" ] && max_line_width="$header_width"

# Process phase rows
for row in "${phase_rows[@]}"; do
  IFS='|' read -r phase samples avg_lat max_lat errors err_rate <<< "$row"
  # Build statistics string
  stats_str=$(printf "samples:%3d avg:%s max:%s errors:%s rate:%s" "$samples" "$avg_lat" "$max_lat" "$errors" "$err_rate")
  
  # Build artifact link for this phase
  if [ "$phase" = "Baseline" ]; then
    phase_link="Latency Metrics (CSV) -> ${CSV_ARTIFACT_URL}"
  elif [ "$phase" = "Chaos" ]; then
    phase_link="Test Summary (TXT) -> ${SUMMARY_ARTIFACT_URL}"
  else
    phase_link="Latency Metrics (CSV) -> ${CSV_ARTIFACT_URL}"
  fi
  
  line=$(printf "%-15s %-100s %s" "$phase" "$phase_link" "$stats_str")
  output_lines+=("$line")
  line_width=$(printf '%s' "$line" | _strip_ansi | wc -c | tr -d ' ')
  [ "$line_width" -gt "$max_line_width" ] && max_line_width="$line_width"
done

# Set banner width to match content
WIDTH=$max_line_width
[ "$WIDTH" -lt 60 ] && WIDTH=60
BAR=$(printf '%*s' "$WIDTH" '' | tr ' ' '=')

# Center text function
banner_center() {
  local line="$1"
  local len=$(printf '%s' "$line" | _strip_ansi | wc -c | tr -d ' ')
  local pad=$(( (WIDTH - len) / 2 ))
  [ $pad -lt 0 ] && pad=0
  printf "%s%*s%s%s\n" "$BANNER_COLOR" "$pad" "" "$line" "$COLOR_RESET"
}

# Print top banner
printf "%s%s%s\n" "$BANNER_COLOR" "$BAR" "$COLOR_RESET"
banner_center "CHAOS ENGINEERING TEST: ${OVERALL_SCORE}/100"
banner_center "STATUS: $TEST_STATUS"
printf "%s%s%s\n" "$BANNER_COLOR" "$BAR" "$COLOR_RESET"

# Print all output lines with proper formatting
for line in "${output_lines[@]}"; do
  if [[ "$line" == *"Phase:"* ]]; then
    # Header row - white color, position "Statistics:" header
    modified_line=$(printf "%-15s %-100s %s" "     Phase:" "Direct Link To Report:" "                           Statistics:")
    printf "%s%s%s\n" "$COLOR_WHITE" "$modified_line" "$COLOR_RESET"
  else
    # Data rows - apply blue color to URLs
    echo "$line" | sed -E "s|(https://[^ ]+)|${COLOR_BLUE}\1${COLOR_RESET}|g"
  fi
done

# Print resilience scores section
printf "%s%s%s\n" "$BANNER_COLOR" "$BAR" "$COLOR_RESET"
echo ""
printf "%s%-30s%s\n" "$COLOR_WHITE" "RESILIENCE SCORES" "$COLOR_RESET"
printf "%-30s %s%3d/100%s\n" "  Latency Tolerance:" "$([ $LATENCY_SCORE -ge 80 ] && echo "$COLOR_GREEN" || echo "$COLOR_RED")" "$LATENCY_SCORE" "$COLOR_RESET"
printf "%-30s %s%3d/100%s\n" "  Error Handling:" "$([ $ERROR_SCORE -ge 80 ] && echo "$COLOR_GREEN" || echo "$COLOR_RED")" "$ERROR_SCORE" "$COLOR_RESET"
printf "%-30s %s%3d/100%s\n" "  Recovery Speed:" "$([ $RECOVERY_SCORE -ge 80 ] && echo "$COLOR_GREEN" || echo "$COLOR_RED")" "$RECOVERY_SCORE" "$COLOR_RESET"
printf "%s%s%s\n" "$BANNER_COLOR" "$BAR" "$COLOR_RESET"

# Generate text summary file
cat > "$CHAOS_DIR/chaos-test-summary.txt" <<EOF
========================================
CHAOS ENGINEERING TEST SUMMARY
========================================
Environment: $CI_ENVIRONMENT_NAME
Base URL: $BASE_URL
Assault Type: $ASSAULT_TYPE
Duration: ${ASSAULT_DURATION} seconds
Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

BASELINE PERFORMANCE
----------------------------------------
Samples:      $BASELINE_SAMPLES
Avg Latency:  ${BASELINE_AVG}ms
Max Latency:  ${BASELINE_MAX}ms
Error Rate:   ${BASELINE_ERROR_RATE}%

CHAOS IMPACT
----------------------------------------
Samples:      $CHAOS_SAMPLES
Avg Latency:  ${CHAOS_AVG}ms (+${LATENCY_INCREASE}%)
Max Latency:  ${CHAOS_MAX}ms
Errors:       $CHAOS_ERRORS
Timeouts:     $CHAOS_TIMEOUT
Error Rate:   ${CHAOS_ERROR_RATE}%

RECOVERY
----------------------------------------
Samples:      $RECOVERY_SAMPLES
Avg Latency:  ${RECOVERY_AVG}ms (${RECOVERY_DIFF}% vs baseline)
Max Latency:  ${RECOVERY_MAX}ms
Error Rate:   ${RECOVERY_ERROR_RATE}%

RESILIENCE SCORE
----------------------------------------
Latency Tolerance:  ${LATENCY_SCORE}/100
Error Handling:     ${ERROR_SCORE}/100
Recovery Speed:     ${RECOVERY_SCORE}/100
----------------------------------------
Overall Score:      ${OVERALL_SCORE}/100
Status:             $TEST_STATUS

========================================
RECOMMENDATIONS
========================================
EOF

if [ $LATENCY_SCORE -lt 80 ]; then
  echo "- Consider implementing circuit breakers for degraded dependencies" >> "$CHAOS_DIR/chaos-test-summary.txt"
  echo "- Review timeout configurations" >> "$CHAOS_DIR/chaos-test-summary.txt"
fi

if [ $ERROR_SCORE -lt 80 ]; then
  echo "- Improve error handling and graceful degradation" >> "$CHAOS_DIR/chaos-test-summary.txt"
  echo "- Add retry logic with exponential backoff" >> "$CHAOS_DIR/chaos-test-summary.txt"
fi

if [ $RECOVERY_SCORE -lt 80 ]; then
  echo "- Investigate resource cleanup and connection pooling" >> "$CHAOS_DIR/chaos-test-summary.txt"
  echo "- Review thread pool configurations" >> "$CHAOS_DIR/chaos-test-summary.txt"
fi

# Exit with appropriate code
if [ $OVERALL_SCORE -lt 40 ]; then
  exit 2
fi

exit 0
