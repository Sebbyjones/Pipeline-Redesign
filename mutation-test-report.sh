#!/usr/bin/env bash
set -euo pipefail
# ANSI color codes (use $'' so escapes are interpreted). Previously these were literal \033 sequences.
COLOR_RESET=$'\033[0m'
COLOR_RED=$'\033[31m'
COLOR_GREEN=$'\033[32m'
COLOR_YELLOW=$'\033[33m'
COLOR_CYAN=$'\033[36m'
COLOR_BLUE=$'\033[34m'
COLOR_BOLD=$'\033[1m'
COLOR_WHITE=$'\033[97m'
GREEN_BRIGHT=$'\033[92m'
RED_BOLD=$'\033[31;1m'
PIT_CLASS_LINKS="${PIT_CLASS_LINKS:-1}"
ESC=$'\033'
PIT_LINK_STYLE="${PIT_LINK_STYLE:-arrow}"  # default arrow for stable display (OSC8 sanitized in GitLab); options: osc8_bel | osc8 | arrow | map | plain
PIT_JSON_INDEX="${PIT_JSON_INDEX:-0}"      # set 1 to emit JSON mapping artifact (pit-class-links.json)
PIT_INLINE_LINKS="${PIT_INLINE_LINKS:-0}"   # default OFF: do not append artifact URL inline; keep lines compact.
PIT_CLASS_INDEX="${PIT_CLASS_INDEX:-1}"  # default ON to provide clickable HTML index artifact
PIT_MARKDOWN_INDEX="${PIT_MARKDOWN_INDEX:-1}"  # optional Markdown index artifact for easy clickable list
PIT_ARTIFACT_URL_MODE="${PIT_ARTIFACT_URL_MODE:-auto}"    # auto | direct | file ; auto tries direct then file pattern. direct: CI_JOB_URL/artifacts/<path>; file: CI_PROJECT_URL/-/jobs/<id>/artifacts/file/<path>
PIT_ARTIFACT_URL_BASE="${PIT_ARTIFACT_URL_BASE:-}"        # override full base (e.g. https://ei-platform.$CI_SERVER_HOST/-/team-vertigo/$CI_PROJECT_NAME/-/jobs/$CI_JOB_ID/artifacts)
PIT_HOST_PREFIX="${PIT_HOST_PREFIX:-}"                    # optional host prefix (e.g. ei-platform) to build https://<prefix>.$CI_SERVER_HOST/... base if PIT_ARTIFACT_URL_BASE unset
PIT_GROUP_PATH_OVERRIDE="${PIT_GROUP_PATH_OVERRIDE:-}"    # override group path portion (e.g. team-vertigo) replacing namespace from CI_PROJECT_URL when base unset
PIT_BANNER_MAX_WIDTH="${PIT_BANNER_MAX_WIDTH:-300}"       # cap banner width to avoid extreme widening from long URL lines
PIT_BANNER_WIDTH_OVERRIDE="${PIT_BANNER_WIDTH_OVERRIDE:-}" # if set, use this fixed banner width (e.g. 118) regardless of content
# Enforce single-line formatting (no separate URL lines, no truncation).
PIT_COMPACT_FORMAT=0
PIT_SHOW_URL_ON_SEPARATE_LINE=0
PIT_URL_TRUNCATE_MODE=none
PIT_SHORT_URL_LABEL="${PIT_SHORT_URL_LABEL:-Coverage Report}"          # Default short label; override to change or empty to show full URL.
PIT_KEEP_FULL_URL_FOR_CLICK="${PIT_KEEP_FULL_URL_FOR_CLICK:-1}" # default 1: show full URL so GitLab auto-link works; set 0 to hide.
PIT_HIDE_LABEL_WHEN_URL="${PIT_HIDE_LABEL_WHEN_URL:-1}"  # Default 1: show only raw URL (Class.java -> URL). Set 0 to include label.
PIT_USE_LABEL_AS_LINK="${PIT_USE_LABEL_AS_LINK:-1}"  # When 1 and hyperlink style (osc8/osc8_bel) used, replaces anchor text with PIT_SHORT_URL_LABEL and hides raw URL.
PIT_HIDE_RAW_URL="${PIT_HIDE_RAW_URL:-1}"  # When 1, raw URL text suppressed if PIT_USE_LABEL_AS_LINK active.
PIT_HYBRID_INLINE_URL="${PIT_HYBRID_INLINE_URL:-0}"  # Default 0: suppress inline URL parentheses; set 1 to show Class.java (https://...).
PIT_HYBRID_PAREN_URL_COLOR="${PIT_HYBRID_PAREN_URL_COLOR:-}"  # Override URL color inside parentheses (e.g. $'\033[30m' for black). Empty uses default white.
PIT_CLASS_SHORT_LINKS="${PIT_CLASS_SHORT_LINKS:-1}"  # DEFAULT ENABLED: create short artifact copies for per-class HTML and use shorter URLs. Set 0 to disable.
# PIT_SHOW_COVERAGE_LABEL_PARENS when 1 appends '(Coverage Report)' after each simple class name before the URL for readability.
PIT_SHOW_COVERAGE_LABEL_PARENS="${PIT_SHOW_COVERAGE_LABEL_PARENS:-1}"  # DEFAULT ENABLED: set 0 to suppress the parenthetical label.
# PIT_FLATTEN_CLASS_HTML when 1 copies the short per-class HTML files to a top-level 'pit-flat/' directory
# to minimize path depth (e.g., .../file/pit-flat/ClassName.html). This further reduces visible URL length
# beyond pit-short's nested path. Set 0 to keep pit-short under the original report root.
PIT_FLATTEN_CLASS_HTML="${PIT_FLATTEN_CLASS_HTML:-0}"
# PIT_TOKENIZED_LINKS when 1 replaces per-class artifact URLs with short token redirect pages
# located under a top-level directory (default 'pit-tokens/'). Each token HTML uses a meta-refresh
# to immediately redirect to the real (possibly long) class report path, keeping log lines compact
# while preserving clickability. Disable by setting PIT_TOKENIZED_LINKS=0.
PIT_TOKENIZED_LINKS="${PIT_TOKENIZED_LINKS:-1}"
# Token configuration: length and directory.
PIT_TOKEN_LENGTH="${PIT_TOKEN_LENGTH:-6}"
PIT_TOKEN_DIR="${PIT_TOKEN_DIR:-pit-tokens}"
# Alias mode (Option B): when enabled (PIT_TOKEN_ALIAS_MODE=1) per-class log lines show only a short token
# (e.g. Class.java (Coverage Report) -> token:Ab12Cd) without the long artifact URL. Clickable navigation
# is provided via separate index artifacts (class index + token index). This keeps the log narrow while
# retaining discoverability. Requires PIT_TOKENIZED_LINKS=1.
PIT_TOKEN_ALIAS_MODE="${PIT_TOKEN_ALIAS_MODE:-1}"
# (Token directory relocation deferred until REPORT_ROOT discovered.)
# PIT_CLASS_SHORT_LINKS details:
#   Problem: Full artifact URLs can be excessively long (group path + project + job id + deep report path), cluttering logs.
#   Behavior when enabled (PIT_CLASS_SHORT_LINKS=1):
#     - A directory 'pit-short' is created under the PIT report root.
#     - Each per-class HTML report is copied to a short, de-duplicated filename (ClassName.html or ClassName_N.html).
#     - Display logic substitutes the short relative path for URL construction, preserving clickability while shortening visible length.
#   Notes:
#     - Copy (not symlink) used for portability inside CI artifact packaging.
#     - If multiple classes share a simple name, numeric suffixes are appended.
#     - Disable by leaving PIT_CLASS_SHORT_LINKS unset or =0; original full per-class paths are used.
#     - Combine with PIT_LINK_STYLE=arrow for "Class.java -> <short URL>" lines.
#     - For further shortening, override PIT_ARTIFACT_URL_BASE to a custom host/base.

ALLOW_EMPTY_MUTATION_REPORT="${ALLOW_EMPTY_MUTATION_REPORT:-false}"  # set true to keep old behavior (non-fatal missing report)

# Dynamic discovery of PIT report directory. Common possibilities:
# 1) fargate/target/pit-reports (module-relative when running with -f fargate/pom.xml)
# 2) target/pit-reports (if module execution changes working dir semantics)
# 3) fargate/fargate/target/pit-reports (if an explicit reportsDirectory incorrectly doubled the module path)
REPORT_ROOT=""
PIT_REPORT_CANDIDATES=("fargate/target/pit-reports" "target/pit-reports" "fargate/fargate/target/pit-reports")
for cand in "${PIT_REPORT_CANDIDATES[@]}"; do
  if [ -d "$cand" ]; then
    REPORT_ROOT="$cand"
    break
  fi
done

if [ -z "$REPORT_ROOT" ]; then
  # Not found in known locations; attempt a broader search (depth 3) for a dir named pit-reports
  FOUND_DIR=$(find . -maxdepth 4 -type d -name pit-reports 2>/dev/null | head -n1 || true)
  if [ -n "$FOUND_DIR" ]; then
    REPORT_ROOT="${FOUND_DIR#./}"  # strip leading ./
  fi
fi

# Relocate token directory inside REPORT_ROOT after discovery (if relative)
if [ -n "${REPORT_ROOT}" ]; then
  case "$PIT_TOKEN_DIR" in
    /*) ;; # absolute
    "$REPORT_ROOT"/*) ;; # already under report root
    *) PIT_TOKEN_DIR="$REPORT_ROOT/${PIT_TOKEN_DIR##./}" ;;
  esac
fi

HTML_INDEX="${REPORT_ROOT:+$REPORT_ROOT/index.html}"
CONSOLE_LOG="${REPORT_ROOT:+$REPORT_ROOT/pitest-console.log}"

if [ -z "$REPORT_ROOT" ] || [ ! -d "$REPORT_ROOT" ]; then
  if [ "$ALLOW_EMPTY_MUTATION_REPORT" = "true" ]; then
    echo -e "${COLOR_YELLOW}[PIT] No PIT report directory found in candidates (${PIT_REPORT_CANDIDATES[*]}) or search. Skipping summary (ALLOW_EMPTY_MUTATION_REPORT=true).${COLOR_RESET}" >&2
    exit 0
  else
    echo -e "${COLOR_RED}[PIT] PIT report directory not found. Checked: ${PIT_REPORT_CANDIDATES[*]}. Set ALLOW_EMPTY_MUTATION_REPORT=true to allow skip.${COLOR_RESET}" >&2
    exit 18
  fi
fi

# Function to build artifact URLs (must be defined before tokenization block)
build_artifact_url() {
  # $1 = relative path under workspace (already stripped ./)
  local rel="$1"
  [ -z "$rel" ] && { printf '%s' ""; return 0; }
  local mode="$PIT_ARTIFACT_URL_MODE"
  # Force 'file' variant when auto is chosen to ensure direct file retrieval stability in GitLab
  if [ "$mode" = "auto" ]; then
    mode="file"
  fi
  local base_override="$PIT_ARTIFACT_URL_BASE"
  local url=""
  if [ -n "$base_override" ]; then
    base_override="${base_override%/}"
    url="${base_override}/${rel}"
  else
    # derive host + group path if overrides present
    local derived_project_url="${CI_PROJECT_URL:-}"
    if [ -n "$PIT_HOST_PREFIX" ] && [ -n "${CI_SERVER_HOST:-}" ]; then
      # Replace host part of CI_PROJECT_URL with prefix variant if possible
      if [ -n "$derived_project_url" ]; then
        local host_part="$(printf '%s' "$derived_project_url" | sed -E 's|https?://([^/]+)/.*|\1|')"
        local rest="$(printf '%s' "$derived_project_url" | sed -E 's|https?://[^/]+/(.*)|\1|')"
        derived_project_url="https://${PIT_HOST_PREFIX}.${CI_SERVER_HOST}/${rest}"
      else
        derived_project_url="https://${PIT_HOST_PREFIX}.${CI_SERVER_HOST}/${PIT_GROUP_PATH_OVERRIDE:+$PIT_GROUP_PATH_OVERRIDE/}${CI_PROJECT_NAME:-}"  # fallback minimal
      fi
    fi
    if [ -n "$PIT_GROUP_PATH_OVERRIDE" ] && [ -n "$derived_project_url" ]; then
      # Replace existing group path with override
      # CI_PROJECT_URL pattern: https://host/<group path>/<project>
      local proto_host="$(printf '%s' "$derived_project_url" | sed -E 's|(https?://[^/]+)/.*|\1|')"
      local proj="${CI_PROJECT_NAME:-$(printf '%s' "$derived_project_url" | sed -E 's|.*/([^/]+)/?$|\1|')}"
      derived_project_url="${proto_host}/${PIT_GROUP_PATH_OVERRIDE}/${proj}"
    fi
    # If auto mode, attempt direct then file variant (direct often 404 if disabled)
    if [ "$mode" = "direct" ]; then
      if [ -n "${CI_JOB_URL:-}" ]; then
        url="${CI_JOB_URL%/}/artifacts/${rel}"
      elif [ -n "${CI_JOB_ID:-}" ] && [ -n "$derived_project_url" ]; then
        url="${derived_project_url}/-/jobs/${CI_JOB_ID}/artifacts/${rel}"
      fi
    fi
    if [ "$mode" = "file" ]; then
      if [ -n "${CI_JOB_ID:-}" ] && [ -n "$derived_project_url" ]; then
        url="${derived_project_url}/-/jobs/${CI_JOB_ID}/artifacts/file/${rel}"
      fi
    fi
  fi
  if [ -z "$url" ] && [ "${PIT_DEBUG:-}" = "1" ]; then
    echo "[PIT][DEBUG] build_artifact_url failed to construct URL for rel='$rel' (mode=$PIT_ARTIFACT_URL_MODE base='$PIT_ARTIFACT_URL_BASE')" >&2
  fi
  printf '%s' "$url"
}

# Pre-scan per-class HTML files to build a fast lookup map keyed by fully qualified class name.
# This avoids multiple recursive find invocations and improves resolution accuracy.
declare -A PIT_HTML_BY_CLASS || true
declare -A PIT_SHORT_PATH_BY_FULL || true
declare -A PIT_FLAT_PATH_BY_FULL || true
declare -A PIT_TOKEN_PATH_BY_FULL || true
declare -A PIT_TOKEN_STRING_BY_FULL || true
if [ -d "$REPORT_ROOT" ]; then
  while IFS= read -r f; do
    rel="${f#${REPORT_ROOT}/}"
    name="${rel%.java.html}"; name="${name%.html}"
    fq="${name//\//.}"
    # Ensure FQ ends with .java segment (mutation XML includes .java-less class names) -> keep original.
    PIT_HTML_BY_CLASS["$fq"]="$f"
  done < <(find "$REPORT_ROOT" -type f \( -name '*.java.html' -o -name '*.html' \) 2>/dev/null || true)
fi

# Optional short link artifact copies (reduces per-line URL length while retaining clickability)
if [ "$PIT_CLASS_SHORT_LINKS" = "1" ] && [ -d "$REPORT_ROOT" ]; then
  SHORT_DIR="$REPORT_ROOT/pit-short"
  mkdir -p "$SHORT_DIR" 2>/dev/null || true
  declare -A _used_short_names || true
  for k in "${!PIT_HTML_BY_CLASS[@]}"; do
    full_path="${PIT_HTML_BY_CLASS[$k]}"
    base_class="${k##*.}"  # simple class name
    short_name="${base_class}.html"
    if [ -n "${_used_short_names[$short_name]:-}" ]; then
      idx=2
      while [ -n "${_used_short_names["${base_class}_${idx}.html"]:-}" ]; do idx=$((idx+1)); done
      short_name="${base_class}_${idx}.html"
    fi
    _used_short_names[$short_name]=1
    short_path="$SHORT_DIR/$short_name"
    # Copy or link (copy guarantees availability across artifact handling scenarios)
    if [ -f "$full_path" ]; then
      cp -f "$full_path" "$short_path" 2>/dev/null || true
      PIT_SHORT_PATH_BY_FULL["$full_path"]="$short_path"
    fi
  done
  # Optional flatten: copy short files to a top-level directory to eliminate deep path segments.
  if [ "$PIT_FLATTEN_CLASS_HTML" = "1" ]; then
    FLAT_DIR="pit-flat"  # top-level relative to workspace root
    mkdir -p "$FLAT_DIR" 2>/dev/null || true
    for full in "${!PIT_SHORT_PATH_BY_FULL[@]}"; do
      short_copy="${PIT_SHORT_PATH_BY_FULL[$full]}"
      flat_target="$FLAT_DIR/$(basename "$short_copy")"
      if [ -f "$short_copy" ]; then
        cp -f "$short_copy" "$flat_target" 2>/dev/null || true
        PIT_FLAT_PATH_BY_FULL["$full"]="$flat_target"
      fi
    done
  fi
fi

# Optional tokenization: create very short redirect HTML pages pointing to the real class report.
if [ "$PIT_TOKENIZED_LINKS" = "1" ]; then
  mkdir -p "$PIT_TOKEN_DIR" 2>/dev/null || true
  _token_collision_guard=1
  for k in "${!PIT_HTML_BY_CLASS[@]}"; do
    full_path="${PIT_HTML_BY_CLASS[$k]}"
    # Resolve effective short/flat path (prefer flattened, then short, else original)
    effective_path="$full_path"
    if [ "$PIT_CLASS_SHORT_LINKS" = "1" ]; then
      if [ "$PIT_FLATTEN_CLASS_HTML" = "1" ] && [ -n "${PIT_FLAT_PATH_BY_FULL[$full_path]:-}" ]; then
        effective_path="${PIT_FLAT_PATH_BY_FULL[$full_path]}"
      elif [ -n "${PIT_SHORT_PATH_BY_FULL[$full_path]:-}" ]; then
        effective_path="${PIT_SHORT_PATH_BY_FULL[$full_path]}"
      fi
    fi
    # Compute relative path from workspace root for redirect target.
    redirect_target="${effective_path#./}"
    # Generate token (base62 from sha256 + job id + class name) truncated to PIT_TOKEN_LENGTH.
    raw_hash=$(printf '%s' "${CI_JOB_ID:-}${k}${redirect_target}" | sha256sum 2>/dev/null | awk '{print $1}')
    # Base62 encode (simple subset: take hex hash, map via groups). Fallback if awk logic fails: use first chars.
    token=""
    if [ -n "$raw_hash" ]; then
      hex_chunk="$raw_hash"
      # Convert each pair of hex to a value then map to 62-char set; stop when length reached.
      base62_chars='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
      i=0
      while [ $i -lt ${#hex_chunk} ] && [ ${#token} -lt "$PIT_TOKEN_LENGTH" ]; do
        pair=${hex_chunk:$i:2}
        dec=$((16#${pair:-0}))
        idx=$(( dec % 62 ))
        token="${token}${base62_chars:$idx:1}"
        i=$((i+2))
      done
    fi
    [ -z "$token" ] && token="${raw_hash:0:$PIT_TOKEN_LENGTH}" || true
    # Ensure uniqueness (rare collisions). Append counter if needed.
    original_token="$token"
    while [ -e "$PIT_TOKEN_DIR/${token}.html" ]; do
      token="${original_token}${_token_collision_guard}"; _token_collision_guard=$((_token_collision_guard+1))
    done
    token_file="$PIT_TOKEN_DIR/${token}.html"
    # Use full artifact URL so redirect does not rely on relative path semantics inside token directory.
    artifact_redirect_url="$(build_artifact_url "$redirect_target")"
    cat > "$token_file" <<EOF || true
  <!doctype html><html><head><meta charset="utf-8"><title>Redirect: ${k}</title><meta http-equiv="refresh" content="0; url=${artifact_redirect_url}"></head><body>
  <p>Redirecting to <code>${k}</code> mutation report...</p>
  <p><a href="${artifact_redirect_url}">Click here if not redirected.</a></p>
  </body></html>
EOF
    PIT_TOKEN_PATH_BY_FULL["$full_path"]="$token_file"
    PIT_TOKEN_STRING_BY_FULL["$full_path"]="$token"
    # Also map short and flat derivative paths to the same token so lookup works regardless of which path find_class_html returns.
    if [ -n "${PIT_SHORT_PATH_BY_FULL[$full_path]:-}" ]; then
      PIT_TOKEN_PATH_BY_FULL["${PIT_SHORT_PATH_BY_FULL[$full_path]}"]="$token_file"
      PIT_TOKEN_STRING_BY_FULL["${PIT_SHORT_PATH_BY_FULL[$full_path]}"]="$token"
    fi
    if [ -n "${PIT_FLAT_PATH_BY_FULL[$full_path]:-}" ]; then
      PIT_TOKEN_PATH_BY_FULL["${PIT_FLAT_PATH_BY_FULL[$full_path]}"]="$token_file"
      PIT_TOKEN_STRING_BY_FULL["${PIT_FLAT_PATH_BY_FULL[$full_path]}"]="$token"
    fi
  done
  # Token files created successfully - no validation needed since redirect targets are artifact URLs, not local paths
fi

# Attempt 1: original timestamp directory heuristic
LATEST_DIR=$(ls -1 "$REPORT_ROOT" 2>/dev/null | sort | tail -n1 || true)
MUT_FILE=""
if [ -n "$LATEST_DIR" ] && [ -f "$REPORT_ROOT/$LATEST_DIR/mutations.xml" ]; then
  MUT_FILE="$REPORT_ROOT/$LATEST_DIR/mutations.xml"
fi

# Attempt 2: find newest mutations.xml by mtime if attempt 1 failed
if [ -z "$MUT_FILE" ]; then
  FOUND=$(find "$REPORT_ROOT" -maxdepth 3 -type f -name mutations.xml -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR==1{print $2}' || true)
  if [ -n "$FOUND" ]; then
    MUT_FILE="$FOUND"
    # Derive directory containing report assets
    LATEST_DIR=$(basename "$(dirname "$MUT_FILE")")
  fi
fi

# Attempt 3: crude glob (in case of deeper nesting)
if [ -z "$MUT_FILE" ]; then
  FOUND_GLOB=$(ls "$REPORT_ROOT"/*/mutations.xml 2>/dev/null | tail -n1 || true)
  if [ -n "$FOUND_GLOB" ]; then
    MUT_FILE="$FOUND_GLOB"
    LATEST_DIR=$(basename "$(dirname "$MUT_FILE")")
  fi
fi

# Attempt 4: deeper search if still not found
if [ -z "$MUT_FILE" ]; then
  FOUND_DEEP=$(find "$REPORT_ROOT" -type f -name mutations.xml 2>/dev/null | head -n1 || true)
  if [ -n "$FOUND_DEEP" ]; then
    MUT_FILE="$FOUND_DEEP"
    LATEST_DIR=$(basename "$(dirname "$MUT_FILE")")
  fi
fi

# Verify mutations.xml has content (at least one <mutation> tag)
if [ -n "$MUT_FILE" ] && [ -f "$MUT_FILE" ]; then
  MUTATION_COUNT=$(grep -c '<mutation ' "$MUT_FILE" 2>/dev/null || echo 0)
  if [ "$MUTATION_COUNT" -eq 0 ]; then
    MUT_FILE=""
  fi
fi

if [ -z "$MUT_FILE" ] || [ ! -f "$MUT_FILE" ]; then
  # Debug: show directory structure
  echo -e "${COLOR_YELLOW}[PIT] mutations.xml not found or empty. Report root contents:${COLOR_RESET}" >&2
  ls -la "$REPORT_ROOT" 2>&1 | head -n 20 | sed 's/^/  /' >&2 || true
  echo -e "${COLOR_YELLOW}[PIT] Searching subdirectories for XML files:${COLOR_RESET}" >&2
  find "$REPORT_ROOT" -maxdepth 2 -name "*.xml" 2>/dev/null | sed 's/^/  /' >&2 || true

  # Attempt console log parsing first (look for earliest statistics block to avoid color or wrapping issues)
  if [ -f "$CONSOLE_LOG" ]; then
    GENERATED_LINE=$(grep -E 'Generated [0-9]+ mutations Killed [0-9]+' "$CONSOLE_LOG" | head -n1 || true)
    NO_COV_LINE=$(grep -E 'Mutations with no coverage [0-9]+' "$CONSOLE_LOG" | head -n1 || true)
    if [ -n "$GENERATED_LINE" ]; then
      TOTAL=$(echo "$GENERATED_LINE" | sed -E 's/.*Generated ([0-9]+) mutations Killed ([0-9]+).*/\1/' || echo 0)
      KILLED=$(echo "$GENERATED_LINE" | sed -E 's/.*Generated ([0-9]+) mutations Killed ([0-9]+).*/\2/' || echo 0)
      SURVIVED=$(( TOTAL - KILLED ))
      if [ -n "$NO_COV_LINE" ]; then
        NO_COVERAGE=$(echo "$NO_COV_LINE" | sed -E 's/.*no coverage ([0-9]+).*/\1/' || echo 0)
      else
        NO_COVERAGE=0
      fi
      TIMED_OUT=0; MEMORY_ERROR=0; RUN_ERROR=0
      PARSE_SOURCE="console"
      echo -e "${COLOR_YELLOW}[PIT] mutations.xml missing; using console log statistics.${COLOR_RESET}" >&2
    fi
  fi
  # If console parsing not successful, fall back to HTML index
  if [ -z "${PARSE_SOURCE:-}" ]; then
    if [ -f "$HTML_INDEX" ]; then
      echo -e "${COLOR_YELLOW}[PIT] mutations.xml missing; parsing HTML index for summary.${COLOR_RESET}" >&2
      STRIPPED=$(sed 's/<[^>]*>//g' "$HTML_INDEX" 2>/dev/null | tr '\r' ' ' || true)
      GENERATED_LINE=$(echo "$STRIPPED" | grep -E 'Generated [0-9]+ mutations Killed [0-9]+' | head -n1 || true)
      NO_COV_LINE=$(echo "$STRIPPED" | grep -E 'Mutations with no coverage [0-9]+' | head -n1 || true)
      if [ -n "$GENERATED_LINE" ]; then
        TOTAL=$(echo "$GENERATED_LINE" | sed -E 's/.*Generated ([0-9]+) mutations Killed ([0-9]+).*/\1/' || echo 0)
        KILLED=$(echo "$GENERATED_LINE" | sed -E 's/.*Generated ([0-9]+) mutations Killed ([0-9]+).*/\2/' || echo 0)
        SURVIVED=$(( TOTAL - KILLED ))
        if [ -n "$NO_COV_LINE" ]; then
          NO_COVERAGE=$(echo "$NO_COV_LINE" | sed -E 's/.*no coverage ([0-9]+).*/\1/' || echo 0)
        else
          NO_COVERAGE=0
        fi
        TIMED_OUT=0; MEMORY_ERROR=0; RUN_ERROR=0
        PARSE_SOURCE="html"
      fi
    else
      echo -e "${COLOR_CYAN}[PIT] Diagnostic listing of $REPORT_ROOT (no mutations.xml & no index.html):${COLOR_RESET}" >&2
      ls -1 "$REPORT_ROOT" 2>&1 | sed 's/^/  /' >&2 || true
      if [ "$ALLOW_EMPTY_MUTATION_REPORT" = "true" ]; then
        echo -e "${COLOR_YELLOW}[PIT] No parsable artifacts; skipping (ALLOW_EMPTY_MUTATION_REPORT=true).${COLOR_RESET}" >&2
        exit 0
      else
        echo -e "${COLOR_RED}[PIT] No mutations.xml or HTML stats found. Failing (set ALLOW_EMPTY_MUTATION_REPORT=true to allow).${COLOR_RESET}" >&2
        exit 18
      fi
    fi
  fi
fi

if [ -n "$MUT_FILE" ] && [ -f "$MUT_FILE" ]; then
  REPORT_DIR="$(dirname "$MUT_FILE")"
  INDEX_HTML="$REPORT_DIR/index.html"
else
  REPORT_DIR="$REPORT_ROOT"
  INDEX_HTML="$HTML_INDEX"
fi
if [ ! -f "$INDEX_HTML" ]; then
  echo -e "${COLOR_YELLOW}[PIT] index.html missing at $INDEX_HTML (continuing with limited data).${COLOR_RESET}" >&2
fi

if [ -n "$MUT_FILE" ] && [ -f "$MUT_FILE" ]; then
  TOTAL=$(grep -c '<mutation ' "$MUT_FILE" 2>/dev/null || echo 0)
  SURVIVED=$(grep -c 'status="SURVIVED"' "$MUT_FILE" 2>/dev/null || echo 0)
  NO_COVERAGE=$(grep -c 'status="NO_COVERAGE"' "$MUT_FILE" 2>/dev/null || echo 0)
  TIMED_OUT=$(grep -c 'status="TIMED_OUT"' "$MUT_FILE" 2>/dev/null || echo 0)
  MEMORY_ERROR=$(grep -c 'status="MEMORY_ERROR"' "$MUT_FILE" 2>/dev/null || echo 0)
  RUN_ERROR=$(grep -c 'status="RUN_ERROR"' "$MUT_FILE" 2>/dev/null || echo 0)
  # Strip any whitespace/newlines and ensure integer values
  TOTAL=$(echo "$TOTAL" | tr -d '\n\r ' | grep -o '[0-9]*' | head -1)
  SURVIVED=$(echo "$SURVIVED" | tr -d '\n\r ' | grep -o '[0-9]*' | head -1)
  NO_COVERAGE=$(echo "$NO_COVERAGE" | tr -d '\n\r ' | grep -o '[0-9]*' | head -1)
  TIMED_OUT=$(echo "$TIMED_OUT" | tr -d '\n\r ' | grep -o '[0-9]*' | head -1)
  MEMORY_ERROR=$(echo "$MEMORY_ERROR" | tr -d '\n\r ' | grep -o '[0-9]*' | head -1)
  RUN_ERROR=$(echo "$RUN_ERROR" | tr -d '\n\r ' | grep -o '[0-9]*' | head -1)
  # Default empty to 0
  : "${TOTAL:=0}"; : "${SURVIVED:=0}"
  : "${NO_COVERAGE:=0}"; : "${TIMED_OUT:=0}"; : "${MEMORY_ERROR:=0}"; : "${RUN_ERROR:=0}"
  # Calculate KILLED as: total - (survived + no_coverage + timed_out + errors)
  KILLED=$((TOTAL - SURVIVED - NO_COVERAGE - TIMED_OUT - MEMORY_ERROR - RUN_ERROR))
  if [ "$KILLED" -lt 0 ]; then KILLED=0; fi
  PARSE_SOURCE="xml"
fi

if [ -z "${PARSE_SOURCE:-}" ] || [ -z "${TOTAL:-}" ] || [ -z "${KILLED:-}" ]; then
  if [ "$ALLOW_EMPTY_MUTATION_REPORT" = "true" ]; then
    echo -e "${COLOR_YELLOW}[PIT] Unable to parse mutation statistics; skipping (ALLOW_EMPTY_MUTATION_REPORT=true).${COLOR_RESET}" >&2
    exit 0
  else
    echo -e "${COLOR_RED}[PIT] Failed to parse mutation statistics from XML, console log, or HTML index.${COLOR_RESET}" >&2
    exit 19
  fi
fi

MUT_SCORE=$(awk -v k="$KILLED" -v t="$TOTAL" 'BEGIN{ if(t>0){ printf("%.2f", (k/t)*100) } else { print "0.00" } }')

# Store original XML-based values for comparison
XML_TOTAL=$TOTAL
XML_KILLED=$KILLED
XML_SURVIVED=$SURVIVED
XML_NO_COVERAGE=$NO_COVERAGE
XML_TIMED_OUT=$TIMED_OUT

# Choose color for mutation score
MS_COLOR="$COLOR_RED"
MS_LABEL="LOW"
if awk -v s="$MUT_SCORE" 'BEGIN{exit !(s >= 75)}'; then
  MS_COLOR="$COLOR_GREEN"; MS_LABEL="GOOD"
elif awk -v s="$MUT_SCORE" 'BEGIN{exit !(s >= 60)}'; then
  MS_COLOR="$COLOR_YELLOW"; MS_LABEL="FAIR"
fi

# Top surviving classes (up to 5) only when XML is available
TOP_SURVIVING=""
if [ -z "${PARSE_FROM_HTML:-}" ] && [ -n "$MUT_FILE" ] && [ -f "$MUT_FILE" ]; then
  TOP_SURVIVING=$(grep 'status="SURVIVED"' "$MUT_FILE" 2>/dev/null | sed -n 's/.*className="\([^"]*\)".*/\1/p' | sort | uniq -c | sort -nr | head -5 || true)
fi

KILLED_PCT=$(awk -v k="$KILLED" -v t="$TOTAL" 'BEGIN{ if(t>0){ printf("%.2f", (k/t)*100) } else { printf("0.00") } }')
SURVIVED_PCT=$(awk -v s="$SURVIVED" -v t="$TOTAL" 'BEGIN{ if(t>0){ printf("%.2f", (s/t)*100) } else { printf("0.00") } }')

# Prepare per-class coverage lines first so banner width can account for the longest line.
_strip_ansi() { sed -E 's/\x1B\[[0-9;]*m//g; s/\x1B]8;;[^\x1B]*\x1B\\//g; s/\x1B]8;;[^\x07]*\x07//g'; }
build_class_display() {
  # Emits only the class name; supports multiple hyperlink styles
  local cls="$1"; local found_html="${2:-}"
  local style="$PIT_LINK_STYLE"
  if [ -z "$found_html" ] && [ -n "$INDEX_HTML" ] && [ -f "$INDEX_HTML" ]; then
    found_html="$INDEX_HTML"
  fi
  local rel_path="${found_html#./}"
  [ -z "$rel_path" ] && rel_path="${INDEX_HTML#./}"
  # If short links active and a short path exists for this full path, substitute
  if [ "$PIT_CLASS_SHORT_LINKS" = "1" ] && [ -n "$found_html" ]; then
    if [ "$PIT_FLATTEN_CLASS_HTML" = "1" ] && [ -n "${PIT_FLAT_PATH_BY_FULL[$found_html]:-}" ]; then
      rel_path="${PIT_FLAT_PATH_BY_FULL[$found_html]#./}"
    elif [ -n "${PIT_SHORT_PATH_BY_FULL[$found_html]:-}" ]; then
      rel_path="${PIT_SHORT_PATH_BY_FULL[$found_html]#./}"
    fi
  fi
  # Tokenization overrides any previous path shortening for display URL.
  if [ "$PIT_TOKENIZED_LINKS" = "1" ] && [ -n "$found_html" ]; then
    # Attempt direct token mapping first (original path key)
    if [ -n "${PIT_TOKEN_PATH_BY_FULL[$found_html]:-}" ]; then
      rel_path="${PIT_TOKEN_PATH_BY_FULL[$found_html]#./}"
    else
      # Fallback: if short/flat substitutions exist, try their token mappings
      if [ "$PIT_CLASS_SHORT_LINKS" = "1" ]; then
        if [ "$PIT_FLATTEN_CLASS_HTML" = "1" ] && [ -n "${PIT_FLAT_PATH_BY_FULL[$found_html]:-}" ]; then
          _flat_key="${PIT_FLAT_PATH_BY_FULL[$found_html]}"
          if [ -n "${_flat_key}" ] && [ -n "${PIT_TOKEN_PATH_BY_FULL[$_flat_key]:-}" ]; then
            rel_path="${PIT_TOKEN_PATH_BY_FULL[$_flat_key]#./}"
          fi
        fi
        # If still not resolved, attempt short path token mapping
        if [ -n "${PIT_SHORT_PATH_BY_FULL[$found_html]:-}" ]; then
          _short_key="${PIT_SHORT_PATH_BY_FULL[$found_html]}"
          if [ -n "${_short_key}" ] && [ -n "${PIT_TOKEN_PATH_BY_FULL[$_short_key]:-}" ]; then
            rel_path="${PIT_TOKEN_PATH_BY_FULL[$_short_key]#./}"
          fi
        fi
      fi
    fi
  fi
  # Centralized URL build (respects PIT_ARTIFACT_URL_BASE + PIT_ARTIFACT_URL_MODE)
  local url=""
  local token_alias=""
  # Always build URL for the token/actual path
  url="$(build_artifact_url "$rel_path")"
  # If token alias mode enabled, also extract token string for display
  if [ "$PIT_TOKEN_ALIAS_MODE" = "1" ] && [ "$PIT_TOKENIZED_LINKS" = "1" ]; then
    # Extract token from mapping (prefer direct path key).
    if [ -n "${PIT_TOKEN_STRING_BY_FULL[$found_html]:-}" ]; then
      token_alias="${PIT_TOKEN_STRING_BY_FULL[$found_html]}"
    else
      # Attempt short/flat keys if original not present.
      if [ -n "${PIT_SHORT_PATH_BY_FULL[$found_html]:-}" ] && [ -n "${PIT_TOKEN_STRING_BY_FULL[${PIT_SHORT_PATH_BY_FULL[$found_html]}]:-}" ]; then
        token_alias="${PIT_TOKEN_STRING_BY_FULL[${PIT_SHORT_PATH_BY_FULL[$found_html]}]}"
      elif [ -n "${PIT_FLAT_PATH_BY_FULL[$found_html]:-}" ] && [ -n "${PIT_TOKEN_STRING_BY_FULL[${PIT_FLAT_PATH_BY_FULL[$found_html]}]:-}" ]; then
        token_alias="${PIT_TOKEN_STRING_BY_FULL[${PIT_FLAT_PATH_BY_FULL[$found_html]}]}"
      fi
    fi
  fi
  local base_name="$cls"
  if [ "$PIT_USE_LABEL_AS_LINK" = "1" ] && [ -n "$PIT_SHORT_URL_LABEL" ] && { [ "$style" = "osc8" ] || [ "$style" = "osc8_bel" ]; }; then
    base_name="$PIT_SHORT_URL_LABEL"
  else
    [[ "$base_name" != *.java ]] && base_name="${base_name}.java"
  fi
  case "$style" in
    osc8_bel)
      if [ -n "$url" ]; then
        # BEL terminator variant ESC ] 8 ; ; URL BEL anchor ESC ] 8 ; ; BEL
        printf '\033]8;;%s\a%s\033]8;;\a' "$url" "$base_name"
      else
        printf '%s' "$base_name"
      fi
      ;;
    osc8)
      if [ -n "$url" ]; then
        # ST terminator variant ESC ] 8 ; ; URL ST anchor ESC ] 8 ; ; ST
        printf '\033]8;;%s\033\\%s\033]8;;\033\\' "$url" "$base_name"
      else
        printf '%s' "$base_name"
      fi
      ;;
    arrow)
      # Arrow style with clickable URL (uses short token URL when available)
      if [ -n "$url" ]; then
        if [ "$PIT_SHOW_COVERAGE_LABEL_PARENS" = "1" ]; then
          printf '%s (Coverage Report) -> %s' "$base_name" "$url"
        else
          printf '%s -> %s' "$base_name" "$url"
        fi
      else
        printf '%s' "$base_name"
      fi
      ;;
    map)
      # Simple mapping format: ClassName URL (space-delimited)
      printf '%s %s' "$base_name" "$url"
      ;;
    plain|*)
      printf '%s' "$base_name"
      ;;
  esac
}
find_class_html() {
  local cls="$1"
  local raw="$cls"
  # If name already ends with .java (from HTML scan path), strip it for lookup
  if [[ "$raw" == *.java ]]; then raw="${raw%.java}"; fi
  # Derive simple class name (last segment after package dots)
  local simple="${raw##*.}"
  local base_name="$simple"
  if [ "${PIT_DEBUG:-}" = "1" ]; then
    echo "[PIT][DEBUG] Resolving class HTML: input='$cls' stripped='$raw' base='$base_name'" >&2
  fi
  # Fast path: exact FQ match from pre-scan map
  if [ -n "${PIT_HTML_BY_CLASS["$raw"]:+x}" ]; then
    printf '%s' "${PIT_HTML_BY_CLASS[$raw]}"
    return 0
  fi
  # Search both REPORT_DIR and REPORT_ROOT recursively (PIT nests by package paths)
  local roots=()
  [ -n "$REPORT_DIR" ] && roots+=("$REPORT_DIR")
  roots+=("$REPORT_ROOT")
  local found=""
  for r in "${roots[@]}"; do
    [ -d "$r" ] || continue
    found=$(find "$r" -type f \( -name "${base_name}.java.html" -o -name "${base_name}.html" \) 2>/dev/null | head -n1 || true)
    [ -n "$found" ] && break
  done
  # Fallback: PIT layout may use dotted package directory (e.g. sf.personalization.java.controller/AggregateController.java.html)
  if [ -z "$found" ]; then
    local pkg_dir="${cls%.*}"   # strip class name from fully qualified
    local cls_only="${cls##*.}" # just the class name
    # Translate package dots into path separators (standard PIT layout)
    local slash_path="${pkg_dir//./\/}"
    local slash_dir="$REPORT_ROOT/$slash_path"
    if [ -d "$slash_dir" ]; then
      if [ -f "$slash_dir/${cls_only}.java.html" ]; then
        found="$slash_dir/${cls_only}.java.html"
      elif [ -f "$slash_dir/${cls_only}.html" ]; then
        found="$slash_dir/${cls_only}.html"
      fi
    fi
    # Non-standard fallback: some builds may actually create dotted directory names (rare)
    if [ -z "$found" ]; then
      local dotted_dir="$REPORT_ROOT/$pkg_dir"
      if [ -d "$dotted_dir" ]; then
        if [ -f "$dotted_dir/${cls_only}.java.html" ]; then
          found="$dotted_dir/${cls_only}.java.html"
        elif [ -f "$dotted_dir/${cls_only}.html" ]; then
          found="$dotted_dir/${cls_only}.html"
        fi
      fi
    fi
  fi
  if [ -n "$found" ]; then
    printf '%s' "$found"
    return 0
  fi
  if [ -z "$found" ] && [ "${PIT_DEBUG:-}" = "1" ]; then
    echo "[PIT][DEBUG] Per-class HTML not found for '$cls'; will fall back to index.html in inline output." >&2
  fi
  # Anchor parse fallback
  if [ -f "$INDEX_HTML" ]; then
    local href
    href=$(grep -Eo 'href="[^\"]*' "$INDEX_HTML" | grep -E "/${base_name}(\.java)?\.html$" | sed 's/href="//' | head -n1 || true)
    if [ -n "$href" ]; then
      for r in "${roots[@]}"; do
        if [ -f "$r/$href" ]; then
          printf '%s' "$r/$href"
          return 0
        fi
      done
    fi
  fi
  if [ "${PIT_DEBUG:-}" = "1" ]; then
    echo "[PIT][DEBUG] HTML for class '$cls' not found" >&2
  fi
  return 1
}
CLASS_COVERAGE_DATA_FILE=$(mktemp || echo "/tmp/pit_class_cov.$$") || true
CLASS_DISPLAY_FILE=$(mktemp || echo "/tmp/pit_class_display.$$") || true
# (Removed hyperlink-map.txt logic; direct per-class links now emitted.)
if [ "${PARSE_SOURCE}" = "xml" ] && [ -f "$MUT_FILE" ]; then
  CLASS_TMP=$(mktemp || echo "/tmp/pit_classes.$$") || true

  # Extract class name and status from mutations.xml
  # Strategy: grep for lines containing what we need, then combine them
  # This is more reliable than trying to parse multi-line XML with sed

  # Extract all mutatedClass values
  CLASSES_FILE=$(mktemp || echo "/tmp/pit_classes_only.$$") || true
  grep -o '<mutatedClass>[^<]*</mutatedClass>' "$MUT_FILE" | sed 's/<mutatedClass>//;s/<\/mutatedClass>//' > "$CLASSES_FILE" 2>/dev/null || true

  # Extract all status values (in same order)
  STATUS_FILE=$(mktemp || echo "/tmp/pit_status_only.$$") || true
  grep -o 'status="[^"]*"' "$MUT_FILE" | sed 's/status="//;s/"//' > "$STATUS_FILE" 2>/dev/null || true

  # Combine them line by line
  paste "$CLASSES_FILE" "$STATUS_FILE" > "$CLASS_TMP" 2>/dev/null || true

  # Debug: show file sizes before cleanup
  CLASSES_COUNT=$(wc -l < "$CLASSES_FILE" 2>/dev/null || echo 0)
  STATUS_COUNT=$(wc -l < "$STATUS_FILE" 2>/dev/null || echo 0)

  # Cleanup temp files
  rm -f "$CLASSES_FILE" "$STATUS_FILE" 2>/dev/null || true

  # Debug: show extraction results (use grep -c for accurate count including last line without newline)
  CLASS_TMP_SIZE=$(grep -c ^ "$CLASS_TMP" 2>/dev/null || echo 0)
  if [ "$CLASS_TMP_SIZE" -eq 0 ]; then
    echo -e "${COLOR_YELLOW}[PIT] DEBUG - extraction failed. Checking XML structure...${COLOR_RESET}" >&2
    echo -e "${COLOR_YELLOW}[PIT] mutatedClass extracted: ${CLASSES_COUNT} lines${COLOR_RESET}" >&2
    echo -e "${COLOR_YELLOW}[PIT] status extracted: ${STATUS_COUNT} lines${COLOR_RESET}" >&2
    echo -e "${COLOR_YELLOW}[PIT] mutatedClass count: $(grep -c '<mutatedClass>' "$MUT_FILE" 2>/dev/null || echo 0)${COLOR_RESET}" >&2
    echo -e "${COLOR_YELLOW}[PIT] status count: $(grep -c "status=" "$MUT_FILE" 2>/dev/null || echo 0)${COLOR_RESET}" >&2
    echo -e "${COLOR_YELLOW}[PIT] First mutation entry:${COLOR_RESET}" >&2
    grep -m 1 '<mutation ' "$MUT_FILE" | head -c 500 >&2 || true
    echo "" >&2
  fi

  # Use pre-scanned HTML files as the authoritative list of classes with mutations
  # Parse mutation stats directly from HTML files since XML may be incomplete
  if [ "${#PIT_HTML_BY_CLASS[@]}" -gt 0 ]; then
    
    _num_or_zero() { local v="$1"; [[ $v =~ ^[0-9]+$ ]] && echo "$v" || echo 0; }

    # Process each class HTML file directly
    for fq_class in "${!PIT_HTML_BY_CLASS[@]}"; do
      html_file="${PIT_HTML_BY_CLASS[$fq_class]}"

      # Parse mutation stats directly from the HTML file
      total=$(grep -c -E 'status="(KILLED|SURVIVED|NO_COVERAGE|TIMED_OUT|RUN_ERROR|MEMORY_ERROR)"' "$html_file" 2>/dev/null || echo 0)
      total=$(_num_or_zero "$total")

      if [ "$total" -eq 0 ]; then
        # Try alternate HTML format without quotes
        total=$(grep -c -E 'KILLED|SURVIVED|NO_COVERAGE|TIMED_OUT|RUN_ERROR|MEMORY_ERROR' "$html_file" 2>/dev/null || echo 0)
        total=$(_num_or_zero "$total")
      fi

      surv=$(grep -c 'SURVIVED' "$html_file" 2>/dev/null || echo 0)
      surv=$(_num_or_zero "$surv")

      no_cov=$(grep -c 'NO_COVERAGE' "$html_file" 2>/dev/null || echo 0)
      no_cov=$(_num_or_zero "$no_cov")

      timed_out=$(grep -c 'TIMED_OUT' "$html_file" 2>/dev/null || echo 0)
      timed_out=$(_num_or_zero "$timed_out")

      # Skip classes with no mutations
      if [ "$total" -eq 0 ]; then continue; fi

      echo "$fq_class $total $surv $no_cov $timed_out"
    done | sort -k1,1 | \
      while read -r cls total surv no_cov timed_out; do
        # Compute coverage percent and colors
        killed=$((total - surv - no_cov - timed_out))
        if [ "$killed" -lt 0 ]; then killed=0; fi
        if [ "$total" -gt 0 ]; then
          pct=$(awk -v k="$killed" -v t="$total" 'BEGIN{ printf("%.2f", (k/t)*100) }')
        else
          pct="0.00"
        fi
        # Color logic: red if any mutations not killed, green if all killed
        # Set individual colors for each metric (0 = green/good, >0 = red/bad)
        if [ "$surv" -gt 0 ]; then surv_color="$RED_BOLD"; else surv_color="$GREEN_BRIGHT"; fi
        if [ "$no_cov" -gt 0 ]; then no_cov_color="$RED_BOLD"; else no_cov_color="$GREEN_BRIGHT"; fi
        if [ "$timed_out" -gt 0 ]; then timed_out_color="$RED_BOLD"; else timed_out_color="$GREEN_BRIGHT"; fi
        # Coverage percentage: red if any failures, green if perfect
        if [ "$surv" -gt 0 ] || [ "$no_cov" -gt 0 ] || [ "$timed_out" -gt 0 ]; then
          pct_color="$RED_BOLD"
        else
          pct_color="$GREEN_BRIGHT"
        fi
        # Attempt to map class to HTML report for clickable link
        found_html="$(find_class_html "$cls")" || true
        display_name="$cls"
        if [ -n "$found_html" ]; then
          display_name="$(build_class_display "$cls" "$found_html")"
        else
          display_name="$(build_class_display "$cls")"
        fi
        # Format: Class  Link  mutations: N survived: N no coverage: N timed out: N coverage: N.NN%
        metrics_line="${COLOR_WHITE}mutations:${COLOR_WHITE}$(printf '%3d' "$total") ${COLOR_WHITE}survived:${surv_color}$(printf '%3d' "$surv") ${COLOR_WHITE}no coverage:${no_cov_color}$(printf '%3d' "$no_cov") ${COLOR_WHITE}timed out:${timed_out_color}$(printf '%3d' "$timed_out") ${COLOR_WHITE}coverage:${pct_color}$(printf '%6.2f' "$pct")%${COLOR_RESET}"
        echo "$display_name  $metrics_line" >> "$CLASS_DISPLAY_FILE" 2>/dev/null || true
        printf "%s %d %d %d %d %.2f\n" "$cls" "$total" "$surv" "$no_cov" "$timed_out" "$pct" >> "$CLASS_COVERAGE_DATA_FILE" 2>/dev/null || true
      done
  else
    echo "(No class details parsed from XML)" >> "$CLASS_DISPLAY_FILE" 2>/dev/null || true
  fi
  rm -f "$CLASS_TMP" || true
elif [ -f "$INDEX_HTML" ]; then
  _num_or_zero() { local v="$1"; [[ $v =~ ^[0-9]+$ ]] && echo "$v" || echo 0; }
  HTML_CLASS_FILES=$(find "$REPORT_ROOT" -type f -name '*.java.html' 2>/dev/null || true)
  if [ -n "$HTML_CLASS_FILES" ]; then
    echo "$HTML_CLASS_FILES" | while read -r f; do
      cls=$(basename "$f" .html)
      total=$(grep -c -E 'status="(KILLED|SURVIVED|NO_COVERAGE|TIMED_OUT|RUN_ERROR|MEMORY_ERROR)"' "$f" 2>/dev/null || echo 0)
      total=$(_num_or_zero "$total")
      if [ "$total" -eq 0 ]; then
        total=$(grep -c -E 'KILLED|SURVIVED|NO_COVERAGE|TIMED_OUT|RUN_ERROR|MEMORY_ERROR' "$f" 2>/dev/null || echo 0)
        total=$(_num_or_zero "$total")
      fi
      survived=$(grep -c 'SURVIVED' "$f" 2>/dev/null || echo 0)
      survived=$(_num_or_zero "$survived")
      if [ "$total" -eq 0 ]; then continue; fi
      if [ "$survived" -eq 0 ]; then
        pct="100.00"; pct_color="$GREEN_BRIGHT"
      else
        pct=$(awk -v t="$total" -v s="$survived" 'BEGIN{ if(t>0){ printf("%.2f", ((t - s)/t)*100) } else { print "0.00" } }'); pct_color="$RED_BOLD"
      fi
  if [ "$survived" -gt 0 ]; then surv_color="$RED_BOLD"; else surv_color="$GREEN_BRIGHT"; fi
      # Mutation count kept white; survived count colored; coverage label white; percentage colored.
      # Hyperlink resolution for class HTML
      display_name="$(build_class_display "$cls" "$f")"
      if [ "$PIT_INLINE_LINKS" = "1" ]; then
        rel_path="${f#./}"; [ -z "$rel_path" ] && rel_path="${INDEX_HTML#./}"
        inline_url="$(build_artifact_url "$rel_path")"
        vis_url="$inline_url"
        if [ "$PIT_COMPACT_FORMAT" = "1" ]; then
          short_seg=""
          if [ "$PIT_URL_DISPLAY_MODE" = "inline_trunc" ]; then
            case "$PIT_URL_TRUNCATE_MODE" in
              filename) short_seg="$(basename "${inline_url}")" ;;
              last2) _tmp="${inline_url#https://}"; _tmp="${_tmp#http://}"; short_seg="$(echo "$_tmp" | awk -F/ '{n=NF; if(n>=2){print $(n-1)"/"$n}else{print $n}}')" ;;
              none|*) short_seg="$(basename "${inline_url}")" ;;
            esac
            metrics_line=$(printf "%s%-40s %smutations:%s%3d %ssurvived:%s%3d %scoverage:%s%6.2f%%%s %s[%s%s%s]%s" \
              "$COLOR_WHITE" "$display_name" \
              "$COLOR_WHITE" "$COLOR_WHITE" "$total" \
              "$COLOR_WHITE" "$surv_color" "$survived" \
              "$COLOR_WHITE" "$pct_color" "$pct" "$COLOR_RESET" \
              "$COLOR_WHITE" "$PIT_URL_TRUNC_LABEL_PREFIX" "$PIT_URL_TRUNC_SEPARATOR" "$short_seg" "$COLOR_RESET")
          else
            metrics_line=$(printf "%s%-40s %smutations:%s%3d %ssurvived:%s%3d %scoverage:%s%6.2f%%%s" \
              "$COLOR_WHITE" "$display_name" \
              "$COLOR_WHITE" "$COLOR_WHITE" "$total" \
              "$COLOR_WHITE" "$surv_color" "$survived" \
              "$COLOR_WHITE" "$pct_color" "$pct" "$COLOR_RESET")
          fi
          printf "%s\n" "$metrics_line" >> "$CLASS_DISPLAY_FILE" 2>/dev/null || true
          if [ "$PIT_SHOW_URL_ON_SEPARATE_LINE" = "1" ]; then
            printf "  %s %s\n" "$PIT_URL_LINE_PREFIX" "${inline_url:-(no-url)}" >> "$CLASS_DISPLAY_FILE" 2>/dev/null || true
          fi
        else
          case "$PIT_URL_TRUNCATE_MODE" in
            filename) vis_url="$(basename "${inline_url}")" ;;
            last2) _tmp="${inline_url#https://}"; _tmp="${_tmp#http://}"; vis_url="$(echo "$_tmp" | awk -F/ '{n=NF; if(n>=2){print $(n-1)"/"$n}else{print $n}}')" ;;
            none|*) ;;
          esac
          printf "%s%-40s %smutations:%s%3d %ssurvived:%s%3d %scoverage:%s%3d%%%s\n" \
            "$COLOR_WHITE" "$display_name" \
            "$COLOR_WHITE" "$COLOR_WHITE" "$total" \
            "$COLOR_WHITE" "$surv_color" "$survived" \
            "$COLOR_WHITE" "$pct_color" "$pct" "$COLOR_RESET" >> "$CLASS_DISPLAY_FILE" 2>/dev/null || true
        fi
      else
        printf "%s%-40s %smutations:%s%3d %ssurvived:%s%3d %scoverage:%s%6.2f%%%s\n" \
          "$COLOR_WHITE" "$display_name" \
          "$COLOR_WHITE" "$COLOR_WHITE" "$total" \
          "$COLOR_WHITE" "$surv_color" "$survived" \
          "$COLOR_WHITE" "$pct_color" "$pct" "$COLOR_RESET" >> "$CLASS_DISPLAY_FILE" 2>/dev/null || true
      fi
      printf "%s %d %d %.2f\n" "$cls" "$total" "$survived" "$pct" >> "$CLASS_COVERAGE_DATA_FILE" 2>/dev/null || true
    done || true
  else
    STRIPPED_IDX=$(sed 's/<[^>]*>/ /g' "$INDEX_HTML" | tr '\n' ' ' | tr -s ' ')
    echo "(No class HTML pages; attempting index.html heuristic)" >&2
    MATCHES=$(echo "$STRIPPED_IDX" | grep -Eo '[A-Za-z0-9_$.]+ +[0-9]+ +[0-9]+ +[0-9]+' || true)
    if [ -z "$MATCHES" ]; then
      echo "(Unable to find class rows in index.html)" >> "$CLASS_DISPLAY_FILE" 2>/dev/null || true
    else
      echo "$MATCHES" | while read -r row; do
        cls=$(echo "$row" | awk '{print $1}')
        killed=$(echo "$row" | awk '{print $2}')
        survived=$(echo "$row" | awk '{print $3}')
        col4=$(echo "$row" | awk '{print $4}')
        killed=$(_num_or_zero "$killed")
        survived=$(_num_or_zero "$survived")
        if [[ $col4 =~ ^[0-9]+$ ]]; then total=$col4; else total=$(( killed + survived )); fi
        total=$(_num_or_zero "$total")
        if [ "$total" -eq 0 ]; then continue; fi
        if [ "$survived" -eq 0 ]; then pct="100.00"; pct_color="$GREEN_BRIGHT"; else pct=$(awk -v t="$total" -v s="$survived" 'BEGIN{ if(t>0){ printf("%.2f", ((t - s)/t)*100) } else { print "0.00" } }'); pct_color="$RED_BOLD"; fi
  if [ "$survived" -gt 0 ]; then surv_color="$RED_BOLD"; else surv_color="$GREEN_BRIGHT"; fi
        if [ "$PIT_INLINE_LINKS" = "1" ]; then
          found_html="$(find_class_html "$cls")" || true
          if [ -n "$found_html" ]; then display_name="$(build_class_display "$cls" "$found_html")"; else display_name="$(build_class_display "$cls")"; fi
          rel_path="${found_html#./}"; [ -z "$rel_path" ] && rel_path="${INDEX_HTML#./}";
          inline_url="$(build_artifact_url "$rel_path")"
          vis_url="$inline_url"
          if [ "$PIT_COMPACT_FORMAT" = "1" ]; then
            short_seg=""
            if [ "$PIT_URL_DISPLAY_MODE" = "inline_trunc" ]; then
              case "$PIT_URL_TRUNCATE_MODE" in
                filename) short_seg="$(basename "${inline_url}")" ;;
                last2) _tmp="${inline_url#https://}"; _tmp="${_tmp#http://}"; short_seg="$(echo "$_tmp" | awk -F/ '{n=NF; if(n>=2){print $(n-1)"/"$n}else{print $n}}')" ;;
                none|*) short_seg="$(basename "${inline_url}")" ;;
              esac
              metrics_line=$(printf "%s%-40s %smutations:%s%3d %ssurvived:%s%3d %scoverage:%s%6.2f%%%s %s[%s%s%s]%s" \
                "$COLOR_WHITE" "$display_name" \
                "$COLOR_WHITE" "$COLOR_WHITE" "$total" \
                "$COLOR_WHITE" "$surv_color" "$survived" \
                "$COLOR_WHITE" "$pct_color" "$pct" "$COLOR_RESET" \
                "$COLOR_WHITE" "$PIT_URL_TRUNC_LABEL_PREFIX" "$PIT_URL_TRUNC_SEPARATOR" "$short_seg" "$COLOR_RESET")
            else
              metrics_line=$(printf "%s%-40s %smutations:%s%3d %ssurvived:%s%3d %scoverage:%s%6.2f%%%s" \
                "$COLOR_WHITE" "$display_name" \
                "$COLOR_WHITE" "$COLOR_WHITE" "$total" \
                "$COLOR_WHITE" "$surv_color" "$survived" \
                "$COLOR_WHITE" "$pct_color" "$pct" "$COLOR_RESET")
            fi
            printf "%s\n" "$metrics_line" >> "$CLASS_DISPLAY_FILE" 2>/dev/null || true
            if [ "$PIT_SHOW_URL_ON_SEPARATE_LINE" = "1" ]; then
              printf "  %s %s\n" "$PIT_URL_LINE_PREFIX" "${inline_url:-(no-url)}" >> "$CLASS_DISPLAY_FILE" 2>/dev/null || true
            fi
          else
            case "$PIT_URL_TRUNCATE_MODE" in
              filename) vis_url="$(basename "${inline_url}")" ;;
              last2) _tmp="${inline_url#https://}"; _tmp="${_tmp#http://}"; vis_url="$(echo "$_tmp" | awk -F/ '{n=NF; if(n>=2){print $(n-1)"/"$n}else{print $n}}')" ;;
              none|*) ;;
            esac
            printf "%s%-40s %smutations:%s%3d %ssurvived:%s%3d %scoverage:%s%6.2f%%%s\n" \
              "$COLOR_WHITE" "$display_name" \
              "$COLOR_WHITE" "$COLOR_WHITE" "$total" \
              "$COLOR_WHITE" "$surv_color" "$survived" \
              "$COLOR_WHITE" "$pct_color" "$pct" "$COLOR_RESET" >> "$CLASS_DISPLAY_FILE" 2>/dev/null || true
          fi
        else
          printf "%s%-40s %smutations:%s%3d %ssurvived:%s%3d %scoverage:%s%6.2f%%%s\n" \
            "$COLOR_WHITE" "$( \
              display_name="$cls"; \
              found_html="$(find_class_html "$cls")" || true; \
              if [ -n "$found_html" ]; then display_name="$(build_class_display "$cls" "$found_html")"; else display_name="$(build_class_display "$cls")"; fi; \
              printf '%s' "$display_name" )" \
            "$COLOR_WHITE" "$COLOR_WHITE" "$total" \
            "$COLOR_WHITE" "$surv_color" "$survived" \
            "$COLOR_WHITE" "$pct_color" "$pct" "$COLOR_RESET" >> "$CLASS_DISPLAY_FILE" 2>/dev/null || true
        fi
        printf "%s %d %d %.2f\n" "$cls" "$total" "$survived" "$pct" >> "$CLASS_COVERAGE_DATA_FILE" 2>/dev/null || true
      done || true
    fi
  fi
else
  echo "Class Mutation Coverage: (unavailable - source: ${PARSE_SOURCE})" >> "$CLASS_DISPLAY_FILE" 2>/dev/null || true
fi

# Rebuild CLASS_DISPLAY_FILE alphabetically by class name (after initial population),
# so banner width calculations reflect sorted output. We sort the raw data file to
# avoid escape sequences interfering with ordering.
if [ -s "$CLASS_COVERAGE_DATA_FILE" ]; then
  mv "$CLASS_DISPLAY_FILE" "$CLASS_DISPLAY_FILE.unsorted" 2>/dev/null || true
  : > "$CLASS_DISPLAY_FILE"
  # Three-column layout: ClassName | URL | Metrics
  declare -a CLASS_NAMES URL_PARTS METRICS_PARTS
  while read -r cls total surv no_cov timed_out pct; do
    # Set individual colors for each metric (0 = green/good, >0 = red/bad)
    if [ "$surv" -gt 0 ]; then surv_color="$RED_BOLD"; else surv_color="$GREEN_BRIGHT"; fi
    if [ "$no_cov" -gt 0 ]; then no_cov_color="$RED_BOLD"; else no_cov_color="$GREEN_BRIGHT"; fi
    if [ "$timed_out" -gt 0 ]; then timed_out_color="$RED_BOLD"; else timed_out_color="$GREEN_BRIGHT"; fi
    # Coverage percentage: red if any failures, green if perfect
    if [ "$surv" -gt 0 ] || [ "$no_cov" -gt 0 ] || [ "$timed_out" -gt 0 ]; then
      pct_color="$RED_BOLD"
    else
      pct_color="$GREEN_BRIGHT"
    fi
    found_html="$(find_class_html "$cls")" || true
    # Build URL for token redirect
    if [ "$PIT_TOKENIZED_LINKS" = "1" ] && [ -n "$found_html" ]; then
      if [ -n "${PIT_TOKEN_PATH_BY_FULL[$found_html]:-}" ]; then
        rel_path="${PIT_TOKEN_PATH_BY_FULL[$found_html]#./}"
      elif [ -n "${PIT_SHORT_PATH_BY_FULL[$found_html]:-}" ]; then
        _short_key="${PIT_SHORT_PATH_BY_FULL[$found_html]}"
        if [ -n "${PIT_TOKEN_PATH_BY_FULL[$_short_key]:-}" ]; then
          rel_path="${PIT_TOKEN_PATH_BY_FULL[$_short_key]#./}"
        fi
      fi
    fi
    url="$(build_artifact_url "$rel_path")"

    # Extract simple class name (last segment after last dot)
    simple_class_name="${cls##*.}"
    [[ "$simple_class_name" != *.java ]] && simple_class_name="${simple_class_name}.java"
    url_segment="${COLOR_BLUE}${url}${COLOR_RESET}"

    # Build metrics display - ALWAYS show all statistics including timed_out (even if 0)
    metrics_segment="${COLOR_WHITE}mutations:${COLOR_WHITE}$(printf '%3d' "$total") ${COLOR_WHITE}survived:${surv_color}$(printf '%3d' "$surv") ${COLOR_WHITE}no coverage:${no_cov_color}$(printf '%3d' "$no_cov") ${COLOR_WHITE}timed out:${timed_out_color}$(printf '%3d' "$timed_out") ${COLOR_WHITE}coverage:${pct_color}$(printf '%6.2f' "$pct")%${COLOR_RESET}"
    CLASS_NAMES+=("$simple_class_name")
    URL_PARTS+=("$url_segment")
    METRICS_PARTS+=("$metrics_segment")
  done < <(awk '{simple=$1; sub(/^.*\./, "", simple); if (simple !~ /\.java$/) simple=simple".java"; print simple"\t"$0}' "$CLASS_COVERAGE_DATA_FILE" | sort -k1,1f | cut -f2-)

  # Determine max class name length (make it global for header use)
  max_class_len=0
  for cn in "${CLASS_NAMES[@]}"; do
    cl=${#cn}
    [ "$cl" -gt "$max_class_len" ] && max_class_len="$cl"
  done

  # Determine max URL length (need to strip ANSI codes for accurate measurement)
  max_url_len=0
  for up in "${URL_PARTS[@]}"; do
    # Strip ANSI color codes to get visible length
    up_clean="${up//$COLOR_BLUE/}"
    up_clean="${up_clean//$COLOR_RESET/}"
    ul=${#up_clean}
    [ "$ul" -gt "$max_url_len" ] && max_url_len="$ul"
  done

  # Determine max metrics length (strip ANSI codes)
  max_metrics_len=0
  for mp in "${METRICS_PARTS[@]}"; do
    # Strip all color codes
    mp_clean="${mp//$COLOR_WHITE/}"
    mp_clean="${mp_clean//$RED_BOLD/}"
    mp_clean="${mp_clean//$GREEN_BRIGHT/}"
    mp_clean="${mp_clean//$COLOR_RESET/}"
    ml=${#mp_clean}
    [ "$ml" -gt "$max_metrics_len" ] && max_metrics_len="$ml"
  done

  # Format with aligned columns
  count=${#CLASS_NAMES[@]}
  for ((i=0;i<count;i++)); do
    cn="${CLASS_NAMES[$i]}"; up="${URL_PARTS[$i]}"; mp="${METRICS_PARTS[$i]}"
    printf '%-*s  %s  %s\n' "$max_class_len" "$cn" "$up" "$mp" >> "$CLASS_DISPLAY_FILE" 2>/dev/null || true
  done

  # Save the column widths for header rendering
  echo "$max_class_len" > "${CLASS_DISPLAY_FILE}.colwidth"
  echo "$max_url_len" > "${CLASS_DISPLAY_FILE}.urlwidth"
  echo "$max_metrics_len" > "${CLASS_DISPLAY_FILE}.metricswidth"
fi

######## Validate XML vs HTML totals and recalculate if XML is incomplete ########
# Aggregate HTML-based totals from CLASS_COVERAGE_DATA_FILE
if [ -s "$CLASS_COVERAGE_DATA_FILE" ]; then
  HTML_TOTAL=0
  HTML_SURVIVED=0
  HTML_NO_COVERAGE=0
  HTML_TIMED_OUT=0
  
  # Sum up totals from all classes in the data file
  # Format: classname total survived no_cov timed_out pct
  while read -r cls total surv no_cov timed_out pct; do
    HTML_TOTAL=$((HTML_TOTAL + total))
    HTML_SURVIVED=$((HTML_SURVIVED + surv))
    HTML_NO_COVERAGE=$((HTML_NO_COVERAGE + no_cov))
    HTML_TIMED_OUT=$((HTML_TIMED_OUT + timed_out))
  done < "$CLASS_COVERAGE_DATA_FILE"
  
  HTML_KILLED=$((HTML_TOTAL - HTML_SURVIVED - HTML_NO_COVERAGE - HTML_TIMED_OUT))
  [ "$HTML_KILLED" -lt 0 ] && HTML_KILLED=0
  
  # Check if XML totals are significantly different (indicates stale cache or incremental analysis issue)
  # XML should have >= HTML totals. If XML < HTML, it's incomplete.
  if [ "$XML_TOTAL" -lt "$HTML_TOTAL" ]; then
    # Override with HTML-based values
    TOTAL=$HTML_TOTAL
    KILLED=$HTML_KILLED
    SURVIVED=$HTML_SURVIVED
    NO_COVERAGE=$HTML_NO_COVERAGE
    TIMED_OUT=$HTML_TIMED_OUT
    
    # Recalculate mutation score
    MUT_SCORE=$(awk -v k="$KILLED" -v t="$TOTAL" 'BEGIN{ if(t>0){ printf("%.2f", (k/t)*100) } else { print "0.00" } }')
  fi
fi

######## Banner setup (dynamic width based on longest class line) ########
WHOLE_SCORE=$(awk -v s="${MUT_SCORE}" 'BEGIN{ printf("%.2f", s) }')
if awk -v s="$WHOLE_SCORE" 'BEGIN{exit !(s >= 100.0)}'; then
  BANNER_COLOR="$GREEN_BRIGHT"; STATUS_TEXT="ALL COVERAGE CHECKS MET!"
else
  BANNER_COLOR="$RED_BOLD"; STATUS_TEXT="COVERAGE CHECKS NOT MET!"
fi
COVERAGE_LINE="MUTATION TEST COVERAGE: ${WHOLE_SCORE}%"
MAX_LEN=0
for candidate in "$COVERAGE_LINE" "$STATUS_TEXT" "Class Mutation Coverage:"; do
  l=$(printf '%s' "$candidate" | _strip_ansi | wc -c | tr -d ' ')
  [ "$l" -gt "$MAX_LEN" ] && MAX_LEN="$l"
done
if [ -s "$CLASS_DISPLAY_FILE" ]; then
  while IFS= read -r line; do
    l=$(printf '%s' "$line" | _strip_ansi | wc -c | tr -d ' ')
    [ "$l" -gt "$MAX_LEN" ] && MAX_LEN="$l"
  done < "$CLASS_DISPLAY_FILE"
fi
WIDTH=$(( MAX_LEN ))
[ -n "$PIT_BANNER_WIDTH_OVERRIDE" ] && WIDTH="$PIT_BANNER_WIDTH_OVERRIDE"
[ "$WIDTH" -gt "$PIT_BANNER_MAX_WIDTH" ] && WIDTH="$PIT_BANNER_MAX_WIDTH"
[ "$WIDTH" -lt 60 ] && WIDTH=60
BAR=$(printf '%*s' "$WIDTH" '' | tr ' ' '=')
banner_center() {
  local text="$1"; local w=$WIDTH
  local len=$(printf '%s' "$text" | _strip_ansi | wc -c | tr -d ' ')
  local pad=$(( (w - len) / 2 ))
  [ $pad -lt 0 ] && pad=0
  printf '%s%*s%s\n' "${BANNER_COLOR}" "$pad" '' "$text${COLOR_RESET}"
}
echo "${BANNER_COLOR}${BAR}${COLOR_RESET}"
banner_center "$COVERAGE_LINE"
banner_center "$STATUS_TEXT"
echo "${BANNER_COLOR}${BAR}${COLOR_RESET}"
echo ""

# Column headers with proper alignment
if [ -s "$CLASS_DISPLAY_FILE" ]; then
  # Read the column widths
  class_col_width=$(cat "${CLASS_DISPLAY_FILE}.colwidth" 2>/dev/null || echo "30")
  url_col_width=$(cat "${CLASS_DISPLAY_FILE}.urlwidth" 2>/dev/null || echo "50")
  metrics_col_width=$(cat "${CLASS_DISPLAY_FILE}.metricswidth" 2>/dev/null || echo "45")

  # Format headers: left-aligned class name, centered URL, right-aligned statistics
  h1="Class Name:"
  h2="Direct Link To Report:"
  h3="Statistics:"

  # Add 5 spaces before h1 to shift it right
  h1_shifted="     ${h1}"

  # Center h2 in url_col_width, then add 6 spaces to shift it right
  h2_pad=$(( (url_col_width - ${#h2}) / 2 ))
  h2_centered="$(printf '%*s' $h2_pad '')      ${h2}"

  # For h3: right-align but shift left by 15 spaces from the right edge
  h3_adjusted_width=$(( metrics_col_width - 15 ))

  # Print header: class column (left-aligned) + centered URL + right-aligned stats (adjusted)
  printf "${COLOR_BOLD}%-*s  %-*s  %*s${COLOR_RESET}\n" "$class_col_width" "$h1_shifted" "$url_col_width" "$h2_centered" "$h3_adjusted_width" "$h3"
  echo "" # Blank line after header
  cat "$CLASS_DISPLAY_FILE"

  # Cleanup temp files
  rm -f "${CLASS_DISPLAY_FILE}.colwidth" "${CLASS_DISPLAY_FILE}.urlwidth" "${CLASS_DISPLAY_FILE}.metricswidth" 2>/dev/null || true

  # Bottom banner matching report width
  echo "${BANNER_COLOR}${BAR}${COLOR_RESET}"
fi
:

SUMMARY_FILE="$REPORT_DIR/summary-banner.txt"
{
  echo "PIT MUTATION TEST SUMMARY"
  echo "Total Mutations : ${TOTAL:-0}"
  echo "Killed          : ${KILLED:-0} (${KILLED_PCT:-0.00}%)"
  echo "Survived        : ${SURVIVED:-0} (${SURVIVED_PCT:-0.00}%)"
  echo "No Coverage     : ${NO_COVERAGE:-0}"
  echo "Errors(Mem/Run) : ${MEMORY_ERROR:-0}/${RUN_ERROR:-0}"
  echo "Mutation Score  : ${MUT_SCORE:-0.00}% ($MS_LABEL)"
  if [ -z "${PARSE_FROM_HTML:-}" ]; then
    echo "Top Surviving Classes (count className)"
    if [ -n "$TOP_SURVIVING" ]; then
      echo "$TOP_SURVIVING" | while read -r count cls; do echo "  $count $cls"; done
    else
      echo "  (none survived or XML unavailable)"
    fi
  else
    echo "Top Surviving Classes: unavailable (parsed from HTML fallback)"
  fi
  echo "Class Mutation Coverage (mutations survived coverage%)"
  if [ -s "$CLASS_COVERAGE_DATA_FILE" ]; then
    cat "$CLASS_COVERAGE_DATA_FILE" | sort -k3,3nr -k1,1
  else
    echo "(no class data collected)"
  fi
} > "$SUMMARY_FILE" || true

# Generate clickable HTML index with class-name links (artifact-friendly)
# Optional class index artifact (disabled unless PIT_CLASS_INDEX=1)
if [ "$PIT_CLASS_INDEX" = "1" ]; then
  INDEX_LINKS_FILE="$REPORT_DIR/pit-class-links.html"
  {
    echo "<!doctype html>"; echo "<html><head><meta charset=\"utf-8\"><title>PIT Class Links</title>"
    echo "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:20px}h1{font-size:20px}table{border-collapse:collapse}th,td{padding:6px 10px;border-bottom:1px solid #ddd}a{color:#0366d6;text-decoration:none}</style>"
    echo "</head><body>"; echo "<h1>PIT Class Report Links</h1>"
    echo "<table><thead><tr><th>Class</th><th>Mutations</th><th>Survived</th><th>Coverage</th></tr></thead><tbody>"
    if [ -s "$CLASS_COVERAGE_DATA_FILE" ]; then
      sort -k1,1 "$CLASS_COVERAGE_DATA_FILE" | while read -r cls total surv pct; do
        found_html="$(find_class_html "$cls")" || true
        if [ -n "$found_html" ]; then
          rel_path="${found_html#./}"
        else
          rel_path="${INDEX_HTML#./}"
        fi
        if [ -n "${CI_PROJECT_URL:-}" ] && [ -n "${CI_JOB_ID:-}" ]; then
          url="${CI_PROJECT_URL}/-/jobs/${CI_JOB_ID}/artifacts/file/${rel_path}"
        else
          url="$rel_path"
        fi
        name_txt="$cls"; [[ "$name_txt" != *.java ]] && name_txt="${name_txt}.java"
        printf '<tr><td><a href="%s">%s</a></td><td>%d</td><td>%d</td><td>%d%%</td></tr>\n' "$url" "$name_txt" "$total" "$surv" "$pct"
      done
    else
      echo "<tr><td colspan=\"4\">(no class data collected)</td></tr>"
    fi
    echo "</tbody></table>"; echo "</body></html>"
  } > "$INDEX_LINKS_FILE" 2>/dev/null || true
  if [ -f "$INDEX_LINKS_FILE" ]; then
    : # Artifact created silently
  fi
fi

# Optional Markdown index artifact (simpler clickable list)
if [ "$PIT_MARKDOWN_INDEX" = "1" ]; then
  MD_INDEX_FILE="$REPORT_DIR/pit-class-links.md"
  {
    echo "# PIT Class Report Links"
    echo "Generated from mutation test run."
    echo ""
    if [ -s "$CLASS_COVERAGE_DATA_FILE" ]; then
      sort -k1,1 "$CLASS_COVERAGE_DATA_FILE" | while read -r cls total surv pct; do
        found_html="$(find_class_html "$cls")" || true
        if [ -n "$found_html" ]; then
          rel_path="${found_html#./}"
        else
          rel_path="${INDEX_HTML#./}"
        fi
        if [ -n "${CI_PROJECT_URL:-}" ] && [ -n "${CI_JOB_ID:-}" ]; then
          url="${CI_PROJECT_URL}/-/jobs/${CI_JOB_ID}/artifacts/file/${rel_path}"
        else
          url="$rel_path"
        fi
        name_txt="$cls"; [[ "$name_txt" != *.java ]] && name_txt="${name_txt}.java"
        echo "- [$name_txt]($url) – mutations: $total, survived: $surv, coverage: $pct%"
      done
    else
      echo "(no class data collected)"
    fi
  } > "$MD_INDEX_FILE" 2>/dev/null || true
  if [ -f "$MD_INDEX_FILE" ]; then
    : # Artifact created silently
  fi
fi

# Optional JSON index artifact (machine-readable mapping)
if [ "$PIT_JSON_INDEX" = "1" ]; then
  JSON_INDEX_FILE="$REPORT_DIR/pit-class-links.json"
  {
    echo '{'
    echo '  "classes": ['
    if [ -s "$CLASS_COVERAGE_DATA_FILE" ]; then
      first=1
      sort -k1,1 "$CLASS_COVERAGE_DATA_FILE" | while read -r cls total survived pct; do
        found_html="$(find_class_html "$cls")" || true
        if [ -n "$found_html" ]; then rel_path="${found_html#./}"; else rel_path="${INDEX_HTML#./}"; fi
        if [ -n "${CI_PROJECT_URL:-}" ] && [ -n "${CI_JOB_ID:-}" ]; then url="${CI_PROJECT_URL}/-/jobs/${CI_JOB_ID}/artifacts/file/${rel_path}"; else url="$rel_path"; fi
        name_txt="$cls"; [[ "$name_txt" != *.java ]] && name_txt="${name_txt}.java"
        [ $first -eq 0 ] && echo ',' || first=0
        printf '    {"name":"%s","mutations":%d,"survived":%d,"coverage":%d,"url":"%s"}' \
          "$name_txt" "$total" "$survived" "$pct" "$url"
      done
      echo ''
    fi
    echo '  ]'
    echo '}'
  } > "$JSON_INDEX_FILE" 2>/dev/null || true
  if [ -f "$JSON_INDEX_FILE" ]; then
    if [ -n "${CI_PROJECT_URL:-}" ] && [ -n "${CI_JOB_ID:-}" ]; then json_rel="${JSON_INDEX_FILE#./}"; json_url="${CI_PROJECT_URL}/-/jobs/${CI_JOB_ID}/artifacts/file/${json_rel}"; echo "[PIT] JSON class index artifact: $JSON_INDEX_FILE" >&2; echo "[PIT] Open JSON links: $json_url" >&2; else echo "[PIT] JSON class index artifact: $JSON_INDEX_FILE (CI URL unavailable)" >&2; fi
  fi
fi

# Optional gating by MIN_MUTATION_SCORE
MIN_MUTATION_SCORE="${MIN_MUTATION_SCORE:-}"  # empty disables gating
if [ -n "$MIN_MUTATION_SCORE" ]; then
  if awk -v s="$MUT_SCORE" -v m="$MIN_MUTATION_SCORE" 'BEGIN{exit !(s < m)}'; then
    echo -e "${COLOR_RED}[PIT] Mutation score ${MUT_SCORE}% below threshold ${MIN_MUTATION_SCORE}%. Failing job.${COLOR_RESET}" >&2
    exit 17
  fi
fi

# Token index artifact (alias navigation) only when alias mode + tokenized links active.
if [ "$PIT_TOKEN_ALIAS_MODE" = "1" ] && [ "$PIT_TOKENIZED_LINKS" = "1" ]; then
  TOKEN_INDEX_FILE="$REPORT_ROOT/pit-token-index.html"
  {
    echo "<!doctype html>"; echo "<html><head><meta charset=\"utf-8\"><title>PIT Token Index</title>";
    echo "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:20px}h1{font-size:20px}table{border-collapse:collapse}th,td{padding:6px 10px;border-bottom:1px solid #ddd}code{background:#f5f5f5;padding:2px 4px;border-radius:4px}</style>";
    echo "</head><body>"; echo "<h1>PIT Token Index</h1>";
    echo "<p>Each token corresponds to a single per-class mutation coverage HTML report. Use this index when log lines are in alias mode (token only).</p>";
    echo "<table><thead><tr><th>Token</th><th>Class</th><th>Report Link</th></tr></thead><tbody>";
    for full_path in "${!PIT_TOKEN_STRING_BY_FULL[@]}"; do
      token="${PIT_TOKEN_STRING_BY_FULL[$full_path]}"
      # Derive class simple name from path (strip .java.html or .html)
      base_file="$(basename "$full_path")"
      cls_name="${base_file%.java.html}"; cls_name="${cls_name%.html}"; [[ "$cls_name" != *.java ]] && cls_name="${cls_name}.java"
      rel="${full_path#./}"; report_url="$(build_artifact_url "$rel")"
      printf '<tr><td><code>%s</code></td><td>%s</td><td><a href="%s">view</a></td></tr>\n' "$token" "$cls_name" "$report_url"
    done | sort -t '>' -k3,3
    echo "</tbody></table>"; echo "</body></html>";
  } > "$TOKEN_INDEX_FILE" 2>/dev/null || true
  if [ -f "$TOKEN_INDEX_FILE" ]; then
    : # Artifact created silently
  fi
fi
