#!/bin/sh
# dependency_coverage.sh
# Unified banner script for Java and Python dependency display.
# Usage:
#   dependency_coverage.sh java
#   dependency_coverage.sh python [BASE_DIR]
# Java prerequisites: Maven build produces dependency_* files + build_exit_code.
# Python prerequisites: pip freeze produces py_requirements_full.txt + py_build_exit_code.

# Use -e (exit on error) only; avoid bash-only vars (BASH_COMMAND) since we run under /bin/sh.
set -e

# Quiet mode: suppress informational/debug lines while keeping the final banner and errors.
# Set DEP_BANNER_QUIET=0 to show all messages again.
quiet_default=1
QUIET=${DEP_BANNER_QUIET:-$quiet_default}

# Override echo to filter out log noise when quiet. We only suppress lines that start with
# [INFO], [DEBUG], [DIAG], or [WARN]. Banner lines do not begin with these prefixes and will still print.
echo() {
  if [ "$QUIET" -eq 1 ]; then
    case "$*" in
      \[INFO\]*|\[DEBUG\]*|\[DIAG\]*|\[WARN\]*) return 0 ;;
    esac
  fi
  command printf '%s\n' "$*"
}
LANG="$1"
if [ -z "$LANG" ]; then echo "[ERROR] First argument must be 'java' or 'python'"; exit 2; fi

if [ "$LANG" = "java" ]; then
  LIST_FILE=fargate/target/dependency_list.txt
  TREE_FILE=fargate/target/dependency_tree.txt
  JAR_LIB_FILE=fargate/target/jar_libs/libs.txt
  RESOLVE_FILE=fargate/target/dependency_resolve.txt
  COPIED_DIR=fargate/target/copied_deps
  AGG_FILE=fargate/target/deps_aggregate.tmp
  CLEAN_FILE=fargate/target/dependencies_clean.txt
  BUCKET_FILE=fargate/target/dependencies_bucketed.txt
  OUT_FILE=fargate/target/dependencies_banner.txt
  rm -f "$AGG_FILE"; : > "$AGG_FILE"
  echo "[INFO] (Java) Aggregating dependency sources for banner..."
  [ -f "$LIST_FILE" ] && echo "[DEBUG] Existing list file size: $(wc -c < "$LIST_FILE" 2>/dev/null)" || echo "[DEBUG] List file missing before aggregation"
  [ -f "$TREE_FILE" ] && echo "[DEBUG] Existing tree file size: $(wc -c < "$TREE_FILE" 2>/dev/null)" || echo "[DEBUG] Tree file missing before aggregation"
  [ -f "$RESOLVE_FILE" ] && echo "[DEBUG] Existing resolve file size: $(wc -c < "$RESOLVE_FILE" 2>/dev/null)" || echo "[DEBUG] Resolve file missing before aggregation"
  if [ -s "$LIST_FILE" ]; then
    sed -E 's/^\[INFO\][[:space:]]*//' "$LIST_FILE" | grep -E '[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+' \
    | awk -F':' '{g=$1;a=$2;third=$3;fourth=$4;fifth=$5; if(g=="org.apache.maven.plugins") next; if(fifth ~ /test/) next; if(fourth=="jar"||fourth=="war"||fourth=="bundle") v=fifth; else if(third=="jar"||third=="war"||third=="bundle") v=fourth; else v=third; if(v=="") v="UNKNOWN"; print g":"a":"v}' >> "$AGG_FILE" || true
  else
    echo "[WARN] (Java) dependency_list.txt missing or empty"
  fi
  if [ -s "$TREE_FILE" ]; then
    echo "[DEBUG] (Java) Parsing dependency_tree.txt entries"
    awk '
      {
        line=$0
        sub(/^\[INFO\][[:space:]]*/, "", line)            # strip Maven INFO prefix
        gsub(/^[-|+\\ ]+/, "", line)                      # strip leading tree glyphs (place - first to avoid range)
        # Only keep coordinates that look like group:artifact:... (avoid noise)
        if (line ~ /[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+/) {
          print line
        }
      }
    ' "$TREE_FILE" | awk -F':' '{g=$1;a=$2;third=$3;fourth=$4;fifth=$5; if(g=="org.apache.maven.plugins") next; if(fifth ~ /test/) next; if(fourth=="jar"||fourth=="war"||fourth=="bundle") v=fifth; else if(third=="jar"||third=="war"||third=="bundle") v=fourth; else v=third; if(v=="") v="UNKNOWN"; print g":"a":"v}' >> "$AGG_FILE" || true
    echo "[DEBUG] (Java) Tree-derived aggregate size now: $(wc -c < "$AGG_FILE" 2>/dev/null)"
  else
    echo "[WARN] (Java) dependency_tree.txt missing or empty"
  fi
  if [ -s "$JAR_LIB_FILE" ]; then
    while IFS= read -r lib; do ver=$(echo "$lib" | sed -nE 's/.*-([0-9][0-9A-Za-z_.-]*)\.jar/\1/p'); base=$(echo "$lib" | sed -E 's/\.jar$//'); art=${base%-${ver}}; [ -z "$ver" ] && ver="UNKNOWN"; echo "embedded.$art:$art:$ver" >> "$AGG_FILE"; done < "$JAR_LIB_FILE"
  else
    echo "[INFO] (Java) No BOOT-INF/lib entries parsed"
  fi
  if [ -s "$RESOLVE_FILE" ]; then
    sed -E 's/^\[INFO\][[:space:]]*//' "$RESOLVE_FILE" | grep -E '[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+:jar:[0-9A-Za-z_.-]+' \
    | awk -F':' '{g=$1;a=$2;pack=$3;v=$4; if(g=="org.apache.maven.plugins") next; if(v=="") v="UNKNOWN"; print g":"a":"v}' >> "$AGG_FILE" || true
  else
    echo "[WARN] (Java) dependency_resolve.txt empty"
  fi
  if [ -d "$COPIED_DIR" ]; then
    echo "[DEBUG] (Java) Introspecting copied_deps jars for pom.properties"
    for jar in "$COPIED_DIR"/*.jar; do
      [ -f "$jar" ] || continue
      props=$(unzip -p "$jar" 'META-INF/maven/*/*/pom.properties' 2>/dev/null | grep -E '^(groupId|artifactId|version)=' | sort -u || true)
      g=$(echo "$props" | grep '^groupId=' | head -n1 | cut -d= -f2)
      a=$(echo "$props" | grep '^artifactId=' | head -n1 | cut -d= -f2)
      v=$(echo "$props" | grep '^version=' | head -n1 | cut -d= -f2)
      if [ -z "$g" ] || [ -z "$a" ]; then
        echo "[DEBUG] (Java) Skipping jar without pom.properties coordinates: $(basename "$jar")"
        continue
      fi
      [ -z "$v" ] && v="UNKNOWN"
      echo "$g:$a:$v" >> "$AGG_FILE"
    done
    echo "[DEBUG] (Java) After copied_deps introspection aggregate size: $(wc -c < "$AGG_FILE" 2>/dev/null)"
  else
    echo "[WARN] (Java) copied_deps directory missing"
  fi
  [ -s "$AGG_FILE" ] && sort -u "$AGG_FILE" > "$CLEAN_FILE"
  echo "[DEBUG] Aggregate temp size: $(wc -c < "$AGG_FILE" 2>/dev/null)"
  if [ ! -s "$LIST_FILE" ]; then echo "[DIAG] List file was not generated. Consider capturing output via tee instead of -DoutputFile."; fi
  if [ ! -s "$TREE_FILE" ]; then echo "[DIAG] Tree file was not generated. Will rely on resolve/copy-dependencies sources."; fi
  [ ! -s "$CLEAN_FILE" ] && echo "sf.personalization.java:java-personalization:${CI_COMMIT_REF_NAME:-unknown}" > "$CLEAN_FILE"
  classify_java() { line="$1"; g=$(echo "$line" | cut -d':' -f1); case "$g" in org.springframework*|org.springdoc*) echo SPRING ;; software.amazon.awssdk*|com.amazonaws*) echo "AWS SDK" ;; org.junit.jupiter*|org.mockito*|io.rest-assured*|org.hamcrest*|com.arcmutate*|org.pitest*|org.assertj*) echo TEST ;; ch.qos.logback*|org.apache.logging*|org.slf4j*|org.apache.tomcat.embed*) echo LOGGING ;; org.springframework.security*|org.owasp*|com.nimbusds*) echo SECURITY ;; com.fasterxml.jackson*|com.google.code.gson*|org.yaml*|net.minidev*) echo SERDE ;; org.springdoc*|io.swagger*|org.openapi*) echo OPENAPI ;; org.apache.commons*|org.projectlombok*|commons-*|com.google.guava*) echo UTIL ;; embedded.*) echo EMBEDDED ;; *) echo OTHER ;; esac }
  # Raw bucket assignments (may contain duplicates across sources)
  TMP_BUCKET_FILE="${BUCKET_FILE}.raw"
  awk 'NF' "$CLEAN_FILE" | while IFS= read -r dep; do bucket=$(classify_java "$dep") || true; echo "$bucket|$dep"; done > "$TMP_BUCKET_FILE"
  # Deduplicate: ensure each artifact:version appears only once, preferring higher priority buckets.
  awk -F'|' '
    function prio(b) {
      if(b=="SPRING") return 10;
      if(b=="AWS SDK") return 9;
      if(b=="SECURITY") return 8;
      if(b=="SERDE") return 7;
      if(b=="OPENAPI") return 6;
      if(b=="LOGGING") return 5;
      if(b=="UTIL") return 4;
      if(b=="TEST") return 3;
      if(b=="EMBEDDED") return 2;
      return 1;
    }
    {
      coord=$2; split(coord, parts, ":"); art=parts[2]; ver=parts[3]; key=art":"ver;
      p=prio($1);
      if(!(key in best) || p>bestp[key]) { best[key]=$0; bestp[key]=p }
    }
    END { for(k in best) print best[k] }
  ' "$TMP_BUCKET_FILE" | sort > "$BUCKET_FILE"
  echo "[DEBUG] After dedup: $(wc -l < "$BUCKET_FILE" 2>/dev/null) entries (raw $(wc -l < "$TMP_BUCKET_FILE" 2>/dev/null))"
  BUILD_RC=$(cat fargate/target/build_exit_code 2>/dev/null || echo 0)
  TOTAL_LABEL="Total unique dependencies: $(wc -l < "$CLEAN_FILE")"
elif [ "$LANG" = "python" ]; then
  BASE_DIR=${2:-lambdas/layer}
  DEP_FILE=$BASE_DIR/py_requirements_full.txt
  EXIT_FILE=$BASE_DIR/py_build_exit_code
  CLEAN_FILE=$BASE_DIR/py_packages_clean.txt
  BUCKET_FILE=$BASE_DIR/py_packages_bucketed.txt
  OUT_FILE=$BASE_DIR/python_dependencies_banner.txt
  [ -f "$DEP_FILE" ] || { echo "[WARN] (Python) $DEP_FILE missing, creating empty"; : > "$DEP_FILE"; }
  echo "[DEBUG] Using DEP_FILE=$DEP_FILE"
  [ -f "$DEP_FILE" ] && echo "[DEBUG] py_requirements_full.txt line count: $(wc -l < "$DEP_FILE" 2>/dev/null)" || echo "[DEBUG] py_requirements_full.txt missing (will create)"
  # Primary source: pip freeze style lines containing 'package==version'
  # Normalize lines: remove CR, trim spaces, keep only package==version patterns
  sed 's/\r$//' "$DEP_FILE" | awk 'NF' | grep -E '==' | sed -E 's/[[:space:]]+//g' | sort -u > "$CLEAN_FILE" || true
  [ -f "$CLEAN_FILE" ] && echo "[DEBUG] Clean file line count: $(wc -l < "$CLEAN_FILE" 2>/dev/null)"
  if [ ! -s "$CLEAN_FILE" ]; then
    echo "[INFO] (Python) Fallback deriving from opt/python contents (dist-info preferred)"
    OPT_DIR="$BASE_DIR/opt/python"
    : > "$CLEAN_FILE"
    if [ -d "$OPT_DIR" ]; then
      for entry in "$OPT_DIR"/*; do
        [ -e "$entry" ] || continue
        namever=$(basename "$entry")
        case "$namever" in
          *.dist-info)
            base=${namever%.dist-info}
            pkg=${base%-*}
            ver=${base#${pkg}-}
            [ -z "$pkg" ] && continue
            [ -z "$ver" ] && ver="UNKNOWN"
            echo "$pkg==$ver" >> "$CLEAN_FILE"
            ;;
          __pycache__|bin)
            ;;
          *)
            if [ -d "$entry" ]; then
              pkg="$namever"
              if ! grep -q "^$pkg==" "$CLEAN_FILE" 2>/dev/null; then
                echo "$pkg==UNKNOWN" >> "$CLEAN_FILE"
              fi
            fi
            ;;
        esac
      done
      sort -u "$CLEAN_FILE" -o "$CLEAN_FILE"
      echo "[DEBUG] Fallback derived line count: $(wc -l < "$CLEAN_FILE" 2>/dev/null)"
    else
      echo "[WARN] opt/python directory missing; cannot derive packages"
    fi
  fi
  classify_py() { pkg="$1"; name=$(echo "$pkg" | awk -F'==' '{print $1}' | tr '[:upper:]' '[:lower:]'); case "$name" in fastapi|django|flask|starlette|uvicorn) echo FRAMEWORK ;; boto3|botocore|aws-*|s3transfer|aws_xray_sdk) echo AWS ;; cryptography|pyjwt|authlib|passlib) echo SECURITY ;; pandas|numpy|scipy|pytz|python-dateutil|sqlalchemy) echo DATA ;; pytest|coverage|hypothesis|parameterized) echo TEST ;; requests|urllib3|idna|charset-normalizer|certifi|chardet) echo UTIL ;; *) echo OTHER ;; esac }
  # Raw bucket assignments
  TMP_PY_BUCKET_FILE="${BUCKET_FILE}.raw"
  awk 'NF' "$CLEAN_FILE" | while IFS= read -r dep; do bucket=$(classify_py "$dep"); echo "$bucket|$dep"; done > "$TMP_PY_BUCKET_FILE"
  # Deduplicate by canonical package name (lowercase, replace underscores with hyphens) preferring real versions over UNKNOWN
  awk -F'|' '
    function canon(n){
      l=tolower(n); gsub("_","-",l); return l;
    }
    {
      pkgver=$2
      split(pkgver, parts, /==/)
      pkg=parts[1]; ver=parts[2]
      c=canon(pkg)
      if(!(c in best) || (bestver[c]=="UNKNOWN" && ver!="UNKNOWN" && ver!="")) { best[c]=$0; bestver[c]= (ver==""?"UNKNOWN":ver) }
    }
    END { for(k in best) print best[k] }
  ' "$TMP_PY_BUCKET_FILE" | sort > "$BUCKET_FILE"
  BUILD_RC=$(cat "$EXIT_FILE" 2>/dev/null || echo 0)
  TOTAL_LABEL="Total unique python packages: $(wc -l < "$CLEAN_FILE")"
  if [ "$(wc -l < "$CLEAN_FILE")" -eq 0 ]; then
    echo "[DIAG] Zero packages detected. Dumping py_requirements_full.txt (first 40 lines if any):"
    head -n40 "$DEP_FILE" || echo "[DIAG] py_requirements_full.txt is empty. Verify pip freeze ran before invoking script."
    echo "[DIAG] Listing opt/python contents:"; ls -1 "$BASE_DIR/opt/python" 2>/dev/null || echo "(empty or missing opt/python)"
  fi
else
  echo "[ERROR] Unknown language '$LANG'"; exit 3
fi

# --- Shared banner rendering with aligned version column ---
# Determine artifact and version column widths
artifact_max=0
version_max=0
while IFS='|' read -r bucket dep; do
  if [ "$LANG" = "java" ]; then
    a=$(echo "$dep" | cut -d':' -f2); v=$(echo "$dep" | cut -d':' -f3)
  else
    # Split on '==': field1=package, field2=version
    a=$(echo "$dep" | awk -F'==' '{print $1}')
    v=$(echo "$dep" | awk -F'==' '{print $2}')
  fi
  [ ${#a} -gt $artifact_max ] && artifact_max=${#a}
  [ ${#v} -gt $version_max ] && version_max=${#v}
done < "$BUCKET_FILE"

# Bucket header widths
bucket_counts=$(awk -F'|' '{c[$1]++} END {for (b in c) printf "%s:%d\n", b, c[b]}' "$BUCKET_FILE")
bucket_count() { echo "$bucket_counts" | awk -F':' -v b="$1" '$1==b {print $2}'; }
header_max=0
while IFS=':' read -r b cnt; do plural=items; [ "$cnt" -eq 1 ] && plural=item; h="[$b - $cnt $plural]"; [ ${#h} -gt $header_max ] && header_max=${#h}; done <<EOF
$bucket_counts
EOF

# Total line width calculation
# Unify Java & Python formatting: dynamic right-aligned version column.
LINE_PREFIX_LEN=2          # leading spaces before artifact
RIGHT_MARGIN=${DEP_BANNER_RIGHT_MARGIN:-0}             # spaces after version before edge (default 0 for strict right alignment)
JAVA_MIN_WIDTH=${DEP_BANNER_JAVA_MIN_WIDTH:-80}
PY_MIN_WIDTH=${DEP_BANNER_PY_MIN_WIDTH:-70}
base_needed=$((LINE_PREFIX_LEN + artifact_max + 1 + version_max + RIGHT_MARGIN))
total_width=$base_needed
[ $header_max -gt $total_width ] && total_width=$header_max
if [ "$LANG" = "java" ]; then
  [ $total_width -lt $JAVA_MIN_WIDTH ] && total_width=$JAVA_MIN_WIDTH
else
  [ $total_width -lt $PY_MIN_WIDTH ] && total_width=$PY_MIN_WIDTH
fi

# Defensive: ensure bucket file exists and is not completely empty to avoid downstream surprises.
if [ ! -f "$BUCKET_FILE" ]; then
  echo "[WARN] Bucket file missing; creating placeholder entry";
  if [ "$LANG" = "java" ]; then echo "OTHER|placeholder:0.0.0" > "$BUCKET_FILE"; else echo "OTHER|placeholder==0.0.0" > "$BUCKET_FILE"; fi
elif [ ! -s "$BUCKET_FILE" ]; then
  echo "[WARN] Bucket file empty; injecting placeholder entry";
  if [ "$LANG" = "java" ]; then echo "OTHER|placeholder:0.0.0" > "$BUCKET_FILE"; else echo "OTHER|placeholder==0.0.0" > "$BUCKET_FILE"; fi
fi

echo "[DEBUG] Width metrics: artifact_max=$artifact_max version_max=$version_max header_max=$header_max total_width=$total_width"

pad_line_total() { txt="$1"; l=${#txt}; pad=$((total_width - l)); printf "%s" "$txt"; [ $pad -gt 0 ] && printf '%*s' $pad ""; }
pad_artifact() { a="$1"; l=${#a}; pad=$((artifact_max - l)); printf "%s" "$a"; [ $pad -gt 0 ] && printf '%*s' $pad ""; }
sep=$(printf '%*s' "$total_width" '' | tr ' ' '=')
COLOR_GREEN='\033[92m'; COLOR_RED='\033[91m'; COLOR_WHITE='\033[97m'; COLOR_BLACK='\033[30m'; RESET='\033[0m'
if [ "$BUILD_RC" -eq 0 ]; then banner_msg="$([ "$LANG" = "java" ] && echo "JAVA PACKAGES SUCCESSFULLY INSTALLED" || echo "PYTHON PACKAGES SUCCESSFULLY INSTALLED")"; else banner_msg="$([ "$LANG" = "java" ] && echo "PACKAGE INSTALLATION FAILED" || echo "PYTHON PACKAGE INSTALLATION FAILED")"; fi
center_pad=$(( (total_width - ${#banner_msg}) / 2 ))

# Bucket spacing configuration (number of blank spacer lines BEFORE each new bucket except the first).
BUCKET_GAP=${DEP_BANNER_BUCKET_GAP:-2}
# Whether to add a blank line after each bucket header (1 = yes, 0 = no)
BUCKET_POST_HEADER_BLANK=${DEP_BANNER_BUCKET_POST_HEADER_BLANK:-1}
# Whether to render a visible spacer line between buckets (1 = yes, 0 = no)
BUCKET_SPACER=${DEP_BANNER_BUCKET_SPACER:-1}
# Character (or short token) to use for spacer if enabled. Default now a thin line.
# Set DEP_BANNER_BUCKET_SPACER_SYMBOL=blank to suppress the visible line; or override to any token (e.g. ·, ---).
BUCKET_SPACER_SYMBOL=${DEP_BANNER_BUCKET_SPACER_SYMBOL:-──}
# Spacer color (ANSI); set DEP_BANNER_BUCKET_SPACER_COLOR to one of: invisible, black, white, green, red or raw escape sequence.
SPACER_COLOR_NAME=${DEP_BANNER_BUCKET_SPACER_COLOR:-black}
COLOR_INVISIBLE='\033[39m'  # Terminal default foreground color (invisible on black terminal)
case "$SPACER_COLOR_NAME" in
  invisible) SPACER_COLOR="$COLOR_INVISIBLE" ;;
  black) SPACER_COLOR="$COLOR_BLACK" ;;
  white) SPACER_COLOR="$COLOR_WHITE" ;;
  green) SPACER_COLOR="$COLOR_GREEN" ;;
  red) SPACER_COLOR="$COLOR_RED" ;;
  none|off|blank) SPACER_COLOR="" ;;
  *) SPACER_COLOR="$SPACER_COLOR_NAME" ;; # allow custom escape like \033[90m
esac

set +e  # Relax error handling during banner rendering to avoid non-critical formatting failures aborting script
{
  printf "%b" "$([ "$BUILD_RC" -eq 0 ] && echo "$COLOR_GREEN" || echo "$COLOR_RED")"
  echo "$sep"
  printf "%*s%s\n" $center_pad "" "$banner_msg"
  echo "$sep"
  printf "%b" "$COLOR_WHITE"
  current=""
  while IFS='|' read -r bucket dep; do
    if [ "$bucket" != "$current" ]; then
      # Insert configurable spacer lines before new bucket (except first bucket)
      if [ -n "$current" ]; then
        # Blank lines first
        i=0
        while [ $i -lt $BUCKET_GAP ]; do echo ""; i=$((i+1)); done
        # Optional visible spacer line (helps when viewer collapses consecutive blanks)
        if [ $BUCKET_SPACER -eq 1 ]; then
          if [ "$BUCKET_SPACER_SYMBOL" = "blank" ]; then
            echo "" # user explicitly requested blank only
          else
            # Center the symbol; if its length >1 we still center approximately.
            sym_len=${#BUCKET_SPACER_SYMBOL}
            left_pad=$(( (total_width - sym_len) / 2 ))
            spacer_line="$(printf '%*s' $left_pad '')${BUCKET_SPACER_SYMBOL}"
            if [ -n "$SPACER_COLOR" ]; then
              printf "%b" "$SPACER_COLOR"
              pad_line_total "$spacer_line"; echo ""
              printf "%b" "$COLOR_WHITE" # revert to content color
            else
              pad_line_total "$spacer_line"; echo ""
            fi
          fi
        fi
      fi
      count=$(bucket_count "$bucket"); plural=items; [ "$count" -eq 1 ] && plural=item
      header_base="[$bucket - $count $plural]"
      # Append right-aligned VERSION label for both languages now
      version_label="VERSION"
      header_pad_len=$(( total_width - ${#header_base} - ${#version_label} ))
      [ $header_pad_len -lt 1 ] && header_pad_len=1
      header_line="${header_base}$(printf '%*s' $header_pad_len '')${version_label}"
      pad_line_total "$header_line"; echo ""
      # Optional blank line after header for readability
      if [ "$BUCKET_POST_HEADER_BLANK" -eq 1 ]; then echo ""; fi
      current="$bucket"
    fi
    if [ "$LANG" = "java" ]; then
      artifact=$(echo "$dep" | cut -d':' -f2); version=$(echo "$dep" | cut -d':' -f3)
    else
      artifact=$(echo "$dep" | awk -F'==' '{print $1}'); version=$(echo "$dep" | awk -F'==' '{print $2}')
    fi
    LINE_PREFIX="  "
    artifact_segment=$(pad_artifact "$artifact")
  version_len=${#version}
  # Gap so that the last character of version sits at (total_width - RIGHT_MARGIN - 1)
  dynamic_gap_len=$(( total_width - LINE_PREFIX_LEN - artifact_max - version_len - RIGHT_MARGIN ))
  [ $dynamic_gap_len -lt 1 ] && dynamic_gap_len=1
  gap_spaces=$(printf '%*s' $dynamic_gap_len '')
  # Compose line exactly; no trailing pad so version ends flush at right edge (minus RIGHT_MARGIN)
  printf "%s%s%s%s\n" "$LINE_PREFIX" "$artifact_segment" "$gap_spaces" "$version"
  done < "$BUCKET_FILE"
  printf "%b" "$([ "$BUILD_RC" -eq 0 ] && echo "$COLOR_GREEN" || echo "$COLOR_RED")"
  echo "$sep"
  pad_line_total "$TOTAL_LABEL"; echo ""
  printf "%b" "$RESET"
} > "$OUT_FILE"
set -e  # Re-enable strict error handling after banner rendering

cat "$OUT_FILE" || echo "[WARN] Failed to cat banner output ($OUT_FILE)"
exit 0
