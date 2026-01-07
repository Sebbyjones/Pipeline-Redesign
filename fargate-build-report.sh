#!/bin/sh
# fargate_build_summary.sh (extended)
# Adds: base image digest, real image size, JAR size & SHA256, cache stats, previous digest delta, JSON output.
# Inputs positional: TAG_NAME, IMG_REGISTRY_PATH, GIT_COMMIT
# Optional env vars:
#   BUILD_LOG, PUSH_LOG, BANNER_WIDTH, DEP_BANNER_QUIET
#   SUMMARY_JSON (path for json output, default fargate/target/fargate_build_summary.json)
#   PREVIOUS_DIGEST_FILE (default fargate/target/last_digest.txt)
#   SHOW_VULN_JSON (path to snyk json to derive vuln summary optional)
#   PRINT_JSON_SUMMARY=1 (echo JSON summary content after banner)

set -e

quiet_default=1
QUIET=${DEP_BANNER_QUIET:-$quiet_default}
echo(){ if [ "$QUIET" -eq 1 ]; then case "$*" in \[INFO\]*|\[DEBUG\]*|\[WARN\]*) return 0 ;; esac; fi; command printf '%s\n' "$*"; }

TAG_NAME="$1"; IMG_REGISTRY_PATH="$2"; GIT_COMMIT="$3"
if [ -z "$TAG_NAME" ] || [ -z "$IMG_REGISTRY_PATH" ]; then echo "[ERROR] TAG_NAME and IMG_REGISTRY_PATH required"; exit 2; fi
BUILD_LOG=${BUILD_LOG:-fargate/target/docker_build.log}
PUSH_LOG=${PUSH_LOG:-fargate/target/docker_push.log}
BANNER_WIDTH=${BANNER_WIDTH:-100}
SUMMARY_JSON=${SUMMARY_JSON:-fargate/target/fargate_build_summary.json}
PREVIOUS_DIGEST_FILE=${PREVIOUS_DIGEST_FILE:-fargate/target/last_digest.txt}
SHOW_VULN_JSON=${SHOW_VULN_JSON:-}

COLOR_GREEN='\033[92m'; COLOR_RED='\033[91m'; COLOR_WHITE='\033[97m'; RESET='\033[0m'

mkdir -p fargate/target

image_ref="${IMG_REGISTRY_PATH}:${TAG_NAME}"
digest=$(grep -E 'digest: sha256:' "$PUSH_LOG" 2>/dev/null | tail -n1 | sed -E 's/.*digest: (sha256:[0-9a-f]{64}).*/\1/' || true)
size_bytes=$(grep -E 'digest: sha256:' "$PUSH_LOG" 2>/dev/null | tail -n1 | sed -nE 's/.*size: ([0-9]+).*/\1/p' || true)
layers_pushed=$(grep -E 'Pushed$' "$PUSH_LOG" 2>/dev/null | wc -l | tr -d ' ')
layers_reused=$(grep -E 'Layer already exists' "$PUSH_LOG" 2>/dev/null | wc -l | tr -d ' ')
cached_steps=$(grep -E ' CACHED$' "$BUILD_LOG" 2>/dev/null | wc -l | tr -d ' ')
total_steps=$(grep -E '^#[0-9]+ ' "$BUILD_LOG" 2>/dev/null | wc -l | tr -d ' ')
raw_done=$(grep -E '^#9 DONE|^#8 DONE|^#5 DONE' "$BUILD_LOG" 2>/dev/null | tail -n1)
build_time=$(echo "$raw_done" | sed -nE 's/.*DONE (.*)/\1/p')
base_image=$(grep -m1 '^#5 \[1/4\] FROM ' "$BUILD_LOG" 2>/dev/null | sed -E 's/.*FROM ([^ ]+).*/\1/' || true)

# Jar info
JAR_PATH=$(ls fargate/docker/*.jar 2>/dev/null | head -n1 || ls fargate/target/*.jar 2>/dev/null | head -n1 || true)
jar_size_bytes=""; jar_sha256=""
if [ -n "$JAR_PATH" ]; then
  jar_size_bytes=$(stat -c %s "$JAR_PATH" 2>/dev/null || echo "")
  jar_sha256=$(sha256sum "$JAR_PATH" 2>/dev/null | awk '{print $1}' || echo "")
fi

# Real image size (may fail if image not locally present)
real_image_size_bytes=""
if command -v docker >/dev/null 2>&1; then
  real_image_size_bytes=$(docker image inspect "$image_ref" --format='{{.Size}}' 2>/dev/null || echo "")
fi

# Previous digest comparison
previous_digest=""
if [ -f "$PREVIOUS_DIGEST_FILE" ]; then previous_digest=$(cat "$PREVIOUS_DIGEST_FILE" 2>/dev/null || true); fi
digest_unchanged="false"
if [ -n "$digest" ] && [ -n "$previous_digest" ] && [ "$digest" = "$previous_digest" ]; then digest_unchanged="true"; fi

# Vulnerability summary (optional)
vuln_summary=""
crit=; high=; med=; low=
if [ -n "$SHOW_VULN_JSON" ] && [ -f "$SHOW_VULN_JSON" ]; then
  # Simple counts: look for "severity":"critical" etc.
  crit=$(grep -o '"severity" *: *"critical"' "$SHOW_VULN_JSON" | wc -l | tr -d ' ')
  high=$(grep -o '"severity" *: *"high"' "$SHOW_VULN_JSON" | wc -l | tr -d ' ')
  med=$(grep -o '"severity" *: *"medium"' "$SHOW_VULN_JSON" | wc -l | tr -d ' ')
  low=$(grep -o '"severity" *: *"low"' "$SHOW_VULN_JSON" | wc -l | tr -d ' ')
  vuln_summary="Vulns (Crit/High/Med/Low): ${crit:-0}/${high:-0}/${med:-0}/${low:-0}"
fi

# Success determination
if [ -n "$digest" ] && [ -s "$BUILD_LOG" ]; then BUILD_SUCCESS=1; else BUILD_SUCCESS=0; fi

# Human readable helpers
to_h_size(){ bytes="$1"; [ -z "$bytes" ] && { echo "unknown"; return; }; if [ "$bytes" -ge 1048576 ]; then awk -v s="$bytes" 'BEGIN{printf "%.2f MB", s/1048576}'; elif [ "$bytes" -ge 1024 ]; then awk -v s="$bytes" 'BEGIN{printf "%.2f KB", s/1024}'; else echo "${bytes} B"; fi; }
manifest_size_h=$(to_h_size "$size_bytes")
real_size_h=$(to_h_size "$real_image_size_bytes")
jar_size_h=$(to_h_size "$jar_size_bytes")

cache_pct=""
if [ "$total_steps" -gt 0 ]; then cache_pct=$(awk -v c="$cached_steps" -v t="$total_steps" 'BEGIN{printf "%.1f%%", (c/t)*100}') ; fi
layer_reuse_pct=""
total_layers_calc=$((layers_pushed + layers_reused))
if [ "$total_layers_calc" -gt 0 ]; then layer_reuse_pct=$(awk -v r="$layers_reused" -v tot="$total_layers_calc" 'BEGIN{printf "%.1f%%", (r/tot)*100}') ; fi

sep=$(printf '%*s' "$BANNER_WIDTH" '' | tr ' ' '=')
center(){ txt="$1"; pad=$(( (BANNER_WIDTH - ${#txt}) / 2 )); [ $pad -lt 0 ] && pad=0; printf "%*s%s\n" $pad "" "$txt"; }
pad_line(){ txt="$1"; l=${#txt}; pad=$((BANNER_WIDTH - l)); printf "%s" "$txt"; [ $pad -gt 0 ] && printf '%*s' $pad ""; printf '\n'; }

status_msg=$( [ $BUILD_SUCCESS -eq 1 ] && echo "FARGATE IMAGE BUILD & PUSH SUCCESS" || echo "FARGATE IMAGE BUILD FAILED" )
color=$( [ $BUILD_SUCCESS -eq 1 ] && echo "$COLOR_GREEN" || echo "$COLOR_RED" )

## First generate JSON so we can optionally embed it inside the banner
cat > "$SUMMARY_JSON" <<JSON
{
  "image": "$image_ref",
  "git_commit": "${GIT_COMMIT:-unknown}",
  "digest": "${digest:-}",
  "previous_digest": "${previous_digest:-}",
  "digest_unchanged": $digest_unchanged,
  "base_image": "${base_image:-}",
  "manifest_size_bytes": ${size_bytes:-0},
  "real_size_bytes": ${real_image_size_bytes:-0},
  "jar_path": "${JAR_PATH:-}",
  "jar_size_bytes": ${jar_size_bytes:-0},
  "jar_sha256": "${jar_sha256:-}",
  "layers": {"pushed": ${layers_pushed:-0}, "reused": ${layers_reused:-0}, "reuse_pct": "${layer_reuse_pct:-}"},
  "steps": {"total": ${total_steps:-0}, "cached": ${cached_steps:-0}, "cache_pct": "${cache_pct:-}"},
  "build_time_raw": "${build_time:-}",
  "vulnerabilities": {"critical": ${crit:-0}, "high": ${high:-0}, "medium": ${med:-0}, "low": ${low:-0}},
  "summary_banner_path": "fargate/target/fargate_build_banner.txt",
  "build_log": "$BUILD_LOG",
  "push_log": "$PUSH_LOG"
}
JSON

{
  printf "%b" "$color"; echo "$sep"; center "$status_msg"; echo "$sep"; printf "%b" "$COLOR_WHITE"
  echo ""
  printf "  %-30s %s\n" "Image:" "$image_ref"
  printf "  %-30s %s\n" "Git Commit:" "${GIT_COMMIT:-unknown}"
  printf "  %-30s %s\n" "Digest:" "${digest:-<none>}"
  printf "  %-30s %s\n" "Manifest Size:" "$manifest_size_h (Real: ${real_size_h})"
  printf "  %-30s %s\n" "JAR Size:" "${jar_size_h}"
  printf "  %-30s %s\n" "JAR SHA256:" "${jar_sha256:-unknown}"
  printf "  %-30s %s\n" "Base Image:" "${base_image:-unknown}"
  printf "  %-30s %s\n" "Layers Pushed:" "$layers_pushed (reused: $layers_reused, ${layer_reuse_pct:-n/a} reuse)"
  printf "  %-30s %s\n" "Build Steps:" "${total_steps} (cached: ${cached_steps}, ${cache_pct:-n/a} cache)"
  printf "  %-30s %s\n" "Build Time:" "${build_time:-unknown}"
  [ -n "$vuln_summary" ] && printf "  %-30s %s\n" "Vulnerabilities:" "$vuln_summary" || true
  printf "  %-30s %s\n" "Previous Digest:" "${previous_digest:-<none>} (unchanged: ${digest_unchanged})"
  printf "  %-30s %s\n" "Build Log:" "${BUILD_LOG}"
  printf "  %-30s %s\n" "Push Log:" "${PUSH_LOG}"
  echo ""
  if [ "${PRINT_JSON_SUMMARY:-0}" -eq 1 ] && [ -f "$SUMMARY_JSON" ]; then
    echo "  JSON Summary:"
    echo "  $(printf '%*s' 90 '' | tr ' ' '-')"
    while IFS= read -r jline; do
      printf "  %s\n" "$jline"
    done < "$SUMMARY_JSON"
    echo ""
  fi
  # Colorize bottom separator same as status color
  printf "%b" "$color"; echo "$sep"; printf "%b" "$RESET"
} > fargate/target/fargate_build_banner.txt

# Persist current digest for next run
if [ -n "$digest" ]; then echo "$digest" > "$PREVIOUS_DIGEST_FILE" 2>/dev/null || true; fi

cat fargate/target/fargate_build_banner.txt || echo "[WARN] Could not display fargate_build_banner.txt"
[ -f "$SUMMARY_JSON" ] || echo "[WARN] JSON summary not generated"

# (External JSON echo removed; JSON now embedded when PRINT_JSON_SUMMARY=1)

[ $BUILD_SUCCESS -eq 1 ] || exit 17
exit 0
