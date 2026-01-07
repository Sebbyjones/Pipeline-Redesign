#!/usr/bin/env bash
# Runs unit tests and prints a Jacoco coverage banner (merged logic from unit_test_coverage.sh).
set -euo pipefail

# Token configuration (matching mutation test approach)
JACOCO_TOKEN_LENGTH="${JACOCO_TOKEN_LENGTH:-6}"
JACOCO_TOKEN_DIR="jacoco-tokens"
JACOCO_SHORT_DIR="jacoco-short"

# URL configuration (matching mutation test approach)
JACOCO_ARTIFACT_URL_MODE="${JACOCO_ARTIFACT_URL_MODE:-auto}"
JACOCO_ARTIFACT_URL_BASE="${JACOCO_ARTIFACT_URL_BASE:-}"
JACOCO_HOST_PREFIX="${JACOCO_HOST_PREFIX:-enterprise-interactions-platform}"
JACOCO_GROUP_PATH_OVERRIDE="${JACOCO_GROUP_PATH_OVERRIDE:--}"

# Build artifact URL - exact copy of mutation test build_artifact_url function
build_artifact_url() {
  # $1 = relative path under workspace (already stripped ./)
  local rel="$1"
  [ -z "$rel" ] && { printf '%s' ""; return 0; }
  local mode="$JACOCO_ARTIFACT_URL_MODE"
  # Force 'file' variant when auto is chosen to ensure direct file retrieval stability in GitLab
  if [ "$mode" = "auto" ]; then
    mode="file"
  fi
  local base_override="$JACOCO_ARTIFACT_URL_BASE"
  local url=""
  if [ -n "$base_override" ]; then
    base_override="${base_override%/}"
    url="${base_override}/${rel}"
  else
    # derive host + group path if overrides present
    local derived_project_url="${CI_PROJECT_URL:-}"
    if [ -n "$JACOCO_HOST_PREFIX" ] && [ -n "${CI_SERVER_HOST:-}" ]; then
      # Replace host part of CI_PROJECT_URL with prefix variant if possible
      if [ -n "$derived_project_url" ]; then
        local host_part="$(printf '%s' "$derived_project_url" | sed -E 's|https?://([^/]+)/.*|\1|')"
        local rest="$(printf '%s' "$derived_project_url" | sed -E 's|https?://[^/]+/(.*)|\1|')"
        derived_project_url="https://${JACOCO_HOST_PREFIX}.${CI_SERVER_HOST}/${rest}"
      else
        derived_project_url="https://${JACOCO_HOST_PREFIX}.${CI_SERVER_HOST}/${JACOCO_GROUP_PATH_OVERRIDE:+$JACOCO_GROUP_PATH_OVERRIDE/}${CI_PROJECT_NAME:-}"  # fallback minimal
      fi
    fi
    if [ -n "$JACOCO_GROUP_PATH_OVERRIDE" ] && [ -n "$derived_project_url" ]; then
      # Replace existing group path with override
      # CI_PROJECT_URL pattern: https://host/<group path>/<project>
      local proto_host="$(printf '%s' "$derived_project_url" | sed -E 's|(https?://[^/]+)/.*|\1|')"
      local proj="${CI_PROJECT_NAME:-$(printf '%s' "$derived_project_url" | sed -E 's|.*/([^/]+)/?$|\1|')}"
      derived_project_url="${proto_host}/${JACOCO_GROUP_PATH_OVERRIDE}/${proj}"
    fi
    # If auto mode, use direct artifacts endpoint (no /file/)
    if [ "$mode" = "direct" ] || [ "$mode" = "file" ]; then
      if [ -n "${CI_JOB_ID:-}" ] && [ -n "$derived_project_url" ]; then
        url="${derived_project_url}/-/jobs/${CI_JOB_ID}/artifacts/${rel}"
      fi
    fi
  fi
  printf '%s' "$url"
}

run_tests() {
  # Temporarily disable pipefail and errexit to handle Maven failures gracefully
  set +e
  set +o pipefail

  mvn -q -f fargate/pom.xml \
    -Dmaven.repo.local=.m2/repository \
    -Dmaven-jfrog.username="$JFROG_USER" \
    -Dmaven-jfrog.password="$JFROG_TEMP_IDENTITY_TOKEN" \
    test -Dtest='!sf.personalization.java.acceptance.*Test,!sf.personalization.java.integration.*IT' \
    -Ddebug=false \
    -Dspring.main.log-startup-info=false \
    -Dlogging.level.root=OFF \
    -Dlogging.level.sf.personalization.java=OFF \
    -Dlogging.level.org.springframework=OFF \
    -Dlogging.level.org.springframework.boot.autoconfigure=ERROR \
    -Dlogback.configurationFile=src/test/resources/logback-test.xml \
    -Dorg.slf4j.simpleLogger.defaultLogLevel=error \
    -Dlogging.pattern.console='' > /dev/null 2>&1
  local test_rc=$?

  # Always generate Jacoco report (even if tests failed)
  mvn -q -f fargate/pom.xml \
    -Dmaven.repo.local=.m2/repository \
    -Dmaven-jfrog.username="$JFROG_USER" \
    -Dmaven-jfrog.password="$JFROG_TEMP_IDENTITY_TOKEN" \
    jacoco:report > /dev/null 2>&1

  # Don't re-enable set -e yet - returning non-zero would exit script
  # Will be re-enabled at script level after print_coverage
  set -o pipefail

  return $test_rc
}

print_coverage() {
  local JACOCO_XML="fargate/target/site/jacoco/jacoco.xml"
  local SUREFIRE_DIR="fargate/target/surefire-reports"

  if [ ! -f "$JACOCO_XML" ]; then
    return 0
  fi

  if ! command -v xmllint >/dev/null 2>&1; then
    return 0
  fi

  # Calculate total coverage
  local total_covered total_missed total total_percent
  total_covered=$(xmllint --xpath "string(//report/counter[@type='LINE']/@covered)" "$JACOCO_XML" 2>/dev/null || echo 0)
  total_missed=$(xmllint --xpath "string(//report/counter[@type='LINE']/@missed)" "$JACOCO_XML" 2>/dev/null || echo 0)
  [[ $total_covered =~ ^[0-9]+$ ]] || total_covered=0
  [[ $total_missed =~ ^[0-9]+$ ]] || total_missed=0
  total=$(( total_covered + total_missed ))
  if [ "$total" -gt 0 ]; then total_percent=$(( 100 * total_covered / total )); else total_percent=0; fi

  local ESC GREEN RED CYAN BLUE NC COLOR
  ESC=$(printf '\033')
  GREEN="${ESC}[92m"; RED="${ESC}[31;1m"; CYAN="${ESC}[36m"; BLUE="${ESC}[34m"; NC="${ESC}[0m"
  if [ "$total_percent" -eq 100 ]; then COLOR="$GREEN"; else COLOR="$RED"; fi

  # Relocate directories to workspace root (matching mutation test pit-tokens at root level)
  local REPORT_ROOT="fargate/target/site/jacoco"
  JACOCO_TOKEN_DIR="fargate/target/$JACOCO_TOKEN_DIR"
  JACOCO_SHORT_DIR="fargate/target/$JACOCO_SHORT_DIR"

  # Create directories
  mkdir -p "$JACOCO_TOKEN_DIR" "$JACOCO_SHORT_DIR" || {
    echo "[COVERAGE] Failed to create token/short directories" >&2
    return 1
  }

  local tmp_classes data_file
  tmp_classes=$(mktemp || echo "/tmp/jacoco_classes.$$") || true
  data_file=$(mktemp || echo "/tmp/jacoco_class_rows.$$") || true

  xmllint --xpath '//class/@name' "$JACOCO_XML" \
    | sed 's/name="/\n/g' \
    | grep -v '^$' \
    | cut -d'"' -f1 \
    | grep -v '\$' \
    | sort -u > "$tmp_classes"

  while read -r name; do
    [ -z "$name" ] && continue
    [ "$name" = "\\" ] && continue
    # Skip inner classes (containing $) - they're already included in parent class coverage
    [[ "$name" == *'$'* ]] && continue

    # Get coverage data
    covered=$(xmllint --xpath "string(//class[@name='$name']/counter[@type='LINE']/@covered)" "$JACOCO_XML" 2>/dev/null || echo 0)
    missed=$(xmllint --xpath "string(//class[@name='$name']/counter[@type='LINE']/@missed)" "$JACOCO_XML" 2>/dev/null || echo 0)
    [[ $covered =~ ^[0-9]+$ ]] || covered=0
    [[ $missed =~ ^[0-9]+$ ]] || missed=0

    local class_total percent pct_color
    class_total=$(( covered + missed ))
    if [ "$class_total" -gt 0 ]; then percent=$(( 100 * covered / class_total )); else percent=0; fi
    if [ "$percent" -lt 100 ]; then pct_color="$RED"; else pct_color="$GREEN"; fi

    # Extract base class name and package path
    local base="${name##*/}"
    local package_path="${name%/*}"
    package_path="${package_path//\//.}"

    # Count tests, failures, and errors for this class by searching surefire XML reports
    local test_count=0 test_failures=0 test_errors=0 test_file_found=""
    if [ -d "$SUREFIRE_DIR" ]; then
      # Look for test files matching pattern TEST-*${base}Test.xml
      local test_file="${SUREFIRE_DIR}/TEST-sf.personalization.java.${base}Test.xml"
      if [ -f "$test_file" ]; then
        test_file_found="$test_file"
      else
        # Try alternative patterns: search all TEST-*.xml files for testcases matching the class
        for xml in "$SUREFIRE_DIR"/TEST-*.xml; do
          [ -f "$xml" ] || continue
          local suite_name=$(xmllint --xpath "string(/testsuite/@name)" "$xml" 2>/dev/null || echo "")
          if [[ "$suite_name" == *"${base}Test" ]]; then
            test_file_found="$xml"
            break
          fi
        done
      fi

      # Extract test counts if file found
      if [ -n "$test_file_found" ]; then
        test_count=$(xmllint --xpath "string(/testsuite/@tests)" "$test_file_found" 2>/dev/null || echo 0)
        test_failures=$(xmllint --xpath "string(/testsuite/@failures)" "$test_file_found" 2>/dev/null || echo 0)
        test_errors=$(xmllint --xpath "string(/testsuite/@errors)" "$test_file_found" 2>/dev/null || echo 0)
        [[ $test_count =~ ^[0-9]+$ ]] || test_count=0
        [[ $test_failures =~ ^[0-9]+$ ]] || test_failures=0
        [[ $test_errors =~ ^[0-9]+$ ]] || test_errors=0
      fi
    fi

    # Calculate test pass rate
    local test_passed=$((test_count - test_failures - test_errors))
    local test_pass_rate=100
    if [ "$test_count" -gt 0 ]; then
      test_pass_rate=$(( 100 * test_passed / test_count ))
    fi

    # Quality score = minimum of coverage% and pass_rate%
    local quality_score=$percent
    if [ "$test_pass_rate" -lt "$quality_score" ]; then
      quality_score=$test_pass_rate
    fi

    # Set color based on quality score (minimum of both metrics)
    if [ "$quality_score" -lt 100 ]; then
      pct_color="$RED"
    else
      pct_color="$GREEN"
    fi

    # Build Jacoco HTML link using exact mutation test approach
    local class_link=""
    if [ -n "${CI_SERVER_HOST:-}" ] && [ -n "${CI_PROJECT_PATH:-}" ] && [ -n "${CI_JOB_ID:-}" ]; then
      # Jacoco directory structure: package uses dots, then class name
      # XML name format: sf/personalization/java/controller/AggregateController
      # Actual Jacoco file: sf.personalization.java.controller/AggregateController.java.html
      # Convert package path (without class) slashes to dots
      local package_part="${name%/*}"  # sf/personalization/java/controller
      local package_dotted="${package_part//\//.}"  # sf.personalization.java.controller

      # Jacoco creates files as package.with.dots/ClassName.java.html
      local jacoco_html_path="fargate/target/site/jacoco/${package_dotted}/${base}.java.html"

      # Create short redirect (pointing to actual Jacoco report with proper styling)
      local short_filename="${base}.html"
      local short_path="$JACOCO_SHORT_DIR/${short_filename}"

      # Build URL to the actual Jacoco HTML report (with full styling and navigation)
      local jacoco_report_relative="fargate/target/site/jacoco/${package_dotted}/${base}.java.html"
      local jacoco_report_url="$(build_artifact_url "$jacoco_report_relative")"

      # Create redirect HTML pointing to the full Jacoco report
      if [ -f "$jacoco_html_path" ]; then
        cat > "$short_path" <<EOF || true
<!doctype html><html><head><meta charset="utf-8"><title>Redirect: ${base}</title><meta http-equiv="refresh" content="0; url=${jacoco_report_url}"></head><body>
<p>Redirecting to <code>${base}.java</code> coverage report...</p>
<p><a href="${jacoco_report_url}">Click here if not redirected.</a></p>
</body></html>
EOF
      else
        echo "[COVERAGE] WARNING: Source not found: $jacoco_html_path" >&2
      fi

      # Generate token (matching PIT tokenization)
      local raw_hash=$(printf '%s' "${CI_JOB_ID:-}${name}${short_path}" | sha256sum 2>/dev/null | awk '{print $1}')
      local token=""
      if [ -n "$raw_hash" ]; then
        local b62chars="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        for ((pos=0; pos<${#raw_hash} && ${#token}<JACOCO_TOKEN_LENGTH; pos+=2)); do
          local hex_pair="${raw_hash:pos:2}"
          local dec=$((16#$hex_pair))
          local idx=$((dec % 62))
          token="${token}${b62chars:idx:1}"
        done
      fi
      [ -z "$token" ] && token="${raw_hash:0:$JACOCO_TOKEN_LENGTH}" || true

      # Create token redirect file (matching PIT approach)
      local token_file="$JACOCO_TOKEN_DIR/${token}.html"
      local short_relative="${short_path#fargate/target/}"
      local target_url="$(build_artifact_url "fargate/target/${short_relative}")"

      cat > "$token_file" <<EOF || true
<!doctype html><html><head><meta charset="utf-8"><title>Redirect: ${base}</title><meta http-equiv="refresh" content="0; url=${target_url}"></head><body>
<p>Redirecting to <code>${base}.java</code> coverage report...</p>
<p><a href="${target_url}">Click here if not redirected.</a></p>
</body></html>
EOF

      # Build token URL (matching PIT_TOKEN_ALIAS_MODE pattern)
      local token_relative="${token_file#fargate/target/}"
      local token_url="$(build_artifact_url "fargate/target/${token_relative}")"

      # Format: ClassName (Coverage Report) -> token_url
      class_link="${base}.java (Coverage Report) -> ${token_url}"
    fi

    # Generate failing tests report token/link if there are failures
    local failing_tests_link=""
    if [ "$test_failures" -gt 0 ] || [ "$test_errors" -gt 0 ]; then
      # Create HTML report for failing tests
      local fail_report_file="$JACOCO_SHORT_DIR/${base}-failures.html"
      cat > "$fail_report_file" <<FAILEOF
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Test Failures: ${base}</title>
<style>
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }
h1 { color: #d32f2f; }
.summary { background: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #d32f2f; }
.test-failure { background: white; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #ff5722; }
.test-name { font-weight: bold; color: #d32f2f; font-size: 1.1em; }
.error-type { color: #f57c00; margin: 5px 0; }
.stack-trace { background: #f5f5f5; padding: 10px; font-family: monospace; font-size: 0.9em; overflow-x: auto; white-space: pre-wrap; }
.suggestion { background: #e3f2fd; padding: 10px; margin-top: 10px; border-radius: 5px; border-left: 3px solid #2196F3; }
.suggestion-title { font-weight: bold; color: #1976D2; }
</style>
</head>
<body>
<h1>❌ Test Failures: ${base}.java</h1>
<div class="summary">
<strong>Class:</strong> ${base}Test<br>
<strong>Total Tests:</strong> ${test_count}<br>
<strong>Failures:</strong> ${test_failures}<br>
<strong>Errors:</strong> ${test_errors}<br>
<strong>Passed:</strong> ${test_passed}
</div>
FAILEOF

      # Parse test failures from Surefire XML
      if [ -n "$test_file_found" ]; then
        # Get count of failing test cases
        local fail_count=$(xmllint --xpath 'count(//testcase[failure or error])' "$test_file_found" 2>/dev/null || echo 0)

        # Process each failing test case
        for ((i=1; i<=fail_count; i++)); do
          # Extract test case details using XPath position
          local test_name=$(xmllint --xpath "string(//testcase[failure or error][$i]/@name)" "$test_file_found" 2>/dev/null || echo "Unknown Test")
          local test_class=$(xmllint --xpath "string(//testcase[failure or error][$i]/@classname)" "$test_file_found" 2>/dev/null || echo "")

          # Try to get failure message (assertion failures)
          local fail_type=$(xmllint --xpath "string(//testcase[failure or error][$i]/failure/@type)" "$test_file_found" 2>/dev/null || echo "")
          local fail_message=$(xmllint --xpath "string(//testcase[failure or error][$i]/failure/@message)" "$test_file_found" 2>/dev/null || echo "")
          local fail_text=$(xmllint --xpath "string(//testcase[failure or error][$i]/failure)" "$test_file_found" 2>/dev/null || echo "")

          # Try to get error message (exceptions)
          local err_type=$(xmllint --xpath "string(//testcase[failure or error][$i]/error/@type)" "$test_file_found" 2>/dev/null || echo "")
          local err_message=$(xmllint --xpath "string(//testcase[failure or error][$i]/error/@message)" "$test_file_found" 2>/dev/null || echo "")
          local err_text=$(xmllint --xpath "string(//testcase[failure or error][$i]/error)" "$test_file_found" 2>/dev/null || echo "")

          # Determine which type of failure this is
          local error_type="Unknown Error"
          local error_message=""
          local stack_trace=""
          local suggestion=""

          if [ -n "$fail_type" ] || [ -n "$fail_message" ]; then
            error_type="Assertion Failure: ${fail_type:-AssertionError}"
            error_message="${fail_message}"
            stack_trace="${fail_text}"

            # Context-aware suggestions for assertion failures
            if [[ "$fail_message" == *"expected"*"but was"* ]] || [[ "$fail_message" == *"Expected"*"Actual"* ]]; then
              suggestion="The test expected a different value than what was returned. Check if:<br>
              • The expected value in the test is correct<br>
              • The production code logic has changed<br>
              • The test data setup matches what the code expects<br>
              • Any data transformations are working as intended"
            elif [[ "$fail_message" == *"NullPointerException"* ]] || [[ "$stack_trace" == *"NullPointerException"* ]]; then
              suggestion="A null value was encountered unexpectedly. Check if:<br>
              • Mock objects are properly initialized<br>
              • Method calls are returning null when they shouldn't<br>
              • Optional values are being handled correctly<br>
              • The object graph is fully constructed before the test"
            elif [[ "$fail_message" == *"path"* ]] || [[ "$fail_message" == *"JSONPath"* ]] || [[ "$fail_message" == *"json"* ]]; then
              suggestion="JSON path or structure mismatch detected. Check if:<br>
              • The JSON structure has changed in the response<br>
              • Field names match exactly (case-sensitive)<br>
              • Nested objects are at the expected depth<br>
              • Array indices are correct"
            else
              suggestion="Review the assertion logic and expected values. Verify the test assumptions match the current code behavior."
            fi
          elif [ -n "$err_type" ] || [ -n "$err_message" ]; then
            error_type="Exception: ${err_type:-Error}"
            error_message="${err_message}"
            stack_trace="${err_text}"

            # Context-aware suggestions for exceptions
            if [[ "$err_type" == *"NullPointerException"* ]]; then
              suggestion="Null pointer encountered during test execution. Check if:<br>
              • All required mocks are configured with @Mock or @MockBean<br>
              • Mock behavior is defined with when().thenReturn()<br>
              • Dependencies are properly injected<br>
              • Test setup methods (@Before, @BeforeEach) are running"
            elif [[ "$err_type" == *"ClassCastException"* ]]; then
              suggestion="Type casting failed. Check if:<br>
              • Return types match what the test expects<br>
              • Generics are properly specified<br>
              • Mock return values have correct types<br>
              • JSON deserialization is creating the right object types"
            elif [[ "$err_type" == *"IllegalArgumentException"* ]] || [[ "$err_type" == *"IllegalStateException"* ]]; then
              suggestion="Invalid argument or state. Check if:<br>
              • Test input values meet validation requirements<br>
              • Objects are in the correct state before method calls<br>
              • Required fields are populated<br>
              • Business rule validations are satisfied"
            else
              suggestion="An exception was thrown during test execution. Review the stack trace to identify the root cause and ensure test setup is complete."
            fi
          fi

          # Extract location information from stack trace (before HTML escaping)
          local error_location=""
          local error_class=""
          local error_line=""
          local error_method=""

          # Parse stack trace for the actual error location (first sf.personalization line)
          if [ -n "$stack_trace" ]; then
            # Look for first line containing sf.personalization (production code, not test)
            error_location=$(echo "$stack_trace" | grep -E 'at sf\.personalization\.java\.[^.]*\.[^.]*\.[^(]*\(' | grep -v 'Test\.java' | head -1)

            if [ -n "$error_location" ]; then
              # Extract class name: sf.personalization.java.service.AggregationService.aggregate
              error_class=$(echo "$error_location" | sed -n 's/.*at \([^(]*\)(.*/\1/p' | sed 's/\.[^.]*$//')
              # Extract method name
              error_method=$(echo "$error_location" | sed -n 's/.*\.\([^.(]*\)(.*/\1/p')
              # Extract line number: AggregationService.java:123
              error_line=$(echo "$error_location" | sed -n 's/.*(\([^:]*:[0-9]*\)).*/\1/p')
            fi

            # If no production code found, check test class location
            if [ -z "$error_location" ]; then
              error_location=$(echo "$stack_trace" | grep -E 'at sf\.personalization\.java\..*Test\.' | head -1)
              if [ -n "$error_location" ]; then
                error_class=$(echo "$error_location" | sed -n 's/.*at \([^(]*\)(.*/\1/p' | sed 's/\.[^.]*$//')
                error_method=$(echo "$error_location" | sed -n 's/.*\.\([^.(]*\)(.*/\1/p')
                error_line=$(echo "$error_location" | sed -n 's/.*(\([^:]*:[0-9]*\)).*/\1/p')
              fi
            fi
          fi

          # Try to extract code snippet if we have file and line number
          local code_snippet=""
          if [ -n "$error_line" ]; then
            local file_name=$(echo "$error_line" | cut -d: -f1)
            local line_num=$(echo "$error_line" | cut -d: -f2)
            
            # Try to find the file in the codebase
            local source_file=""
            if [ -f "fargate/src/main/java/${error_class//./\/}.java" ]; then
              source_file="fargate/src/main/java/${error_class//./\/}.java"
            elif [ -f "fargate/src/test/java/${error_class//./\/}.java" ]; then
              source_file="fargate/src/test/java/${error_class//./\/}.java"
            fi
            
            # Extract code context (5 lines before and after)
            if [ -n "$source_file" ] && [ -f "$source_file" ] && [ -n "$line_num" ]; then
              local start_line=$((line_num - 3))
              [ $start_line -lt 1 ] && start_line=1
              local end_line=$((line_num + 3))
              
              code_snippet=$(awk -v start="$start_line" -v end="$end_line" -v target="$line_num" '
                NR >= start && NR <= end {
                  if (NR == target) {
                    printf "→ %4d | %s\n", NR, $0
                  } else {
                    printf "  %4d | %s\n", NR, $0
                  }
                }
              ' "$source_file" 2>/dev/null || echo "")
            fi
          fi

          # HTML escape the content for safe display
          error_message=$(echo "$error_message" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
          stack_trace=$(echo "$stack_trace" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
          code_snippet=$(echo "$code_snippet" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')

          # Limit stack trace length
          stack_trace=$(echo "$stack_trace" | head -c 2000)

          cat >> "$fail_report_file" <<TESTEOF
<div class="test-failure">
<div class="test-name">Test: ${test_name}</div>
<div class="error-type">Type: ${error_type}</div>
$([ -n "$error_message" ] && echo "<div class=\"error-type\">Message: ${error_message}</div>")
$([ -n "$error_class" ] && echo "<div class=\"error-type\"><strong>Error Class:</strong> ${error_class}</div>")
$([ -n "$error_method" ] && echo "<div class=\"error-type\"><strong>Error Method:</strong> ${error_method}()</div>")
$([ -n "$error_line" ] && echo "<div class=\"error-type\"><strong>Location:</strong> ${error_line}</div>")
$([ -n "$code_snippet" ] && cat <<CODEEOF
<div class="error-type" style="margin-top: 10px;"><strong>Code Context:</strong></div>
<div class="stack-trace" style="background: #fff3cd; border-left: 3px solid #ffc107;">
${code_snippet}
</div>
CODEEOF
)
<div class="stack-trace">${stack_trace}</div>
<div class="suggestion">
<div class="suggestion-title">💡 Potential Fix:</div>
${suggestion}
</div>
</div>
TESTEOF
        done
      fi

      echo "</body></html>" >> "$fail_report_file"

      # Generate token for failing tests report
      local fail_raw_hash=$(printf '%s' "${CI_JOB_ID:-}fail${name}" | sha256sum 2>/dev/null | awk '{print $1}')
      local fail_token=""
      if [ -n "$fail_raw_hash" ]; then
        local b62chars="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        for ((pos=0; pos<${#fail_raw_hash} && ${#fail_token}<JACOCO_TOKEN_LENGTH; pos+=2)); do
          local hex_pair="${fail_raw_hash:pos:2}"
          local dec=$((16#$hex_pair))
          local idx=$((dec % 62))
          fail_token="${fail_token}${b62chars:idx:1}"
        done
      fi
      [ -z "$fail_token" ] && fail_token="${fail_raw_hash:0:$JACOCO_TOKEN_LENGTH}" || true

      local fail_token_file="$JACOCO_TOKEN_DIR/${fail_token}.html"
      local fail_short_relative="${fail_report_file#fargate/target/}"
      local fail_target_url="$(build_artifact_url "fargate/target/${fail_short_relative}")"

      cat > "$fail_token_file" <<FAILTOKEN
<!doctype html><html><head><meta charset="utf-8"><title>Failures: ${base}</title><meta http-equiv="refresh" content="0; url=${fail_target_url}"></head><body>
<p>Redirecting to test failures for <code>${base}.java</code>...</p>
<p><a href="${fail_target_url}">Click here if not redirected.</a></p>
</body></html>
FAILTOKEN

      local fail_token_relative="${fail_token_file#fargate/target/}"
      failing_tests_link="$(build_artifact_url "fargate/target/${fail_token_relative}")"
    fi

    # Store: basename|coverage_link|tests|passed|failed|errors|coverage_percent|quality_score|failing_tests_link|colorCode
    printf "%s|%s|%d|%d|%d|%d|%d|%d|%s|%s\n" \
      "${base}.java" "$class_link" "$test_count" "$test_passed" "$test_failures" "$test_errors" \
      "$percent" "$quality_score" "$failing_tests_link" "$pct_color" >> "$data_file"
  done < "$tmp_classes"

  # Helper function to strip ANSI codes for width calculation
  _strip_ansi() { sed -E 's/\x1B\[[0-9;]*m//g'; }

  # Build all output lines first to calculate maximum width
  local output_lines=()
  local max_line_width=0

  # Add header line to output with proper formatting
  # Stats section width: 10 + 3 + 12 + 3 + 12 + 3 + 12 = 55 characters
  local stats_header=$(printf "%10s | %12s | %12s | %12s" "Tests" "Coverage" "Passing" "Failed")
  # Position stats to the right, after Class Name (35) and URL (165)
  local header_line=$(printf "%-35s %-165s %s" "Class Name:" "" "$stats_header")
  output_lines+=("$header_line")
  local header_width=$(printf '%s' "$header_line" | _strip_ansi | wc -c | tr -d ' ')
  [ "$header_width" -gt "$max_line_width" ] && max_line_width="$header_width"

  # Process all data rows and calculate width
  while IFS='|' read -r base cov_link tests passed failed errors coverage quality fail_link color_code; do
    # Determine color for coverage (green if 100%, red otherwise)
    local cov_color="$GREEN"
    if [ "$coverage" -lt 100 ]; then cov_color="$RED"; fi

    # Determine color for passing tests (green if all passed, red otherwise)
    local passing_color="$color_code"

    # Calculate total failed
    local total_failed=$((failed + errors))
    local failed_color="$GREEN"
    if [ "$total_failed" -gt 0 ]; then
      failed_color="$RED"
    fi

    # Format statistics with fixed-width columns for proper alignment
    local stats_str=$(printf "%10d | %s%12s%s | %s%12d%s | %s%12d%s" \
      "$tests" \
      "$cov_color" "${coverage}%" "$NC" \
      "$passing_color" "$passed" "$NC" \
      "$failed_color" "$total_failed" "$NC")
    # Extract just the URL from the coverage link (remove "ClassName (Coverage Report) -> " prefix)
    local url_only="${cov_link##* -> }"
    local line=$(printf "%-35s %-165s %s" "$base" "$url_only" "$stats_str")
    output_lines+=("$line")
    local line_width=$(printf '%s' "$line" | _strip_ansi | wc -c | tr -d ' ')
    [ "$line_width" -gt "$max_line_width" ] && max_line_width="$line_width"

    # If there are failed tests AND coverage is 100%, add a second line with the failed tests report
    if [ "$total_failed" -gt 0 ] && [ "$coverage" -eq 100 ] && [ -n "$fail_link" ]; then
      # Create indented line with visual connector (└─) to show it belongs to the class above
      # Format: 2 spaces + connector + label (left column), then URL aligned in the middle column
      local fail_line=$(printf "  ${RED}└─ Failed Tests Report:${NC} %10s%-165s" "" "$fail_link")
      output_lines+=("$fail_line")
      local fail_line_width=$(printf '%s' "$fail_line" | _strip_ansi | wc -c | tr -d ' ')
      [ "$fail_line_width" -gt "$max_line_width" ] && max_line_width="$fail_line_width"
    fi
  done < <(sort -f -t '|' -k1,1 "$data_file")

  # Calculate totals from the data file (new format: field 8 is quality_score)
  local total_tests=$(awk -F'|' '{sum+=$3} END {print sum}' "$data_file")
  local total_classes=$(wc -l < "$data_file")
  local classes_below_100=$(awk -F'|' '$8<100 {count++} END {print count+0}' "$data_file")

  # Calculate weighted average quality score across all classes
  # Weight by number of tests in each class (field 3 = test_count, field 8 = quality_score)
  local weighted_quality=$(awk -F'|' '
    {
      weighted_sum += $3 * $8;
      total_tests_sum += $3;
    }
    END {
      if (total_tests_sum > 0) {
        print int(weighted_sum / total_tests_sum);
      } else {
        print 100;
      }
    }
  ' "$data_file")
  [ -z "$weighted_quality" ] && weighted_quality=100

  # Adjust total_percent by combining raw coverage with weighted quality score
  # Formula: combined = min(raw_coverage%, weighted_quality%)
  if [ "$weighted_quality" -lt "$total_percent" ]; then
    total_percent=$weighted_quality
  fi
  
  # Update color based on combined metric
  if [ "$total_percent" -eq 100 ]; then COLOR="$GREEN"; else COLOR="$RED"; fi

  # Set banner width to match content
  local width=$max_line_width
  local border=$(printf '%*s' "$width" '' | tr ' ' '=')

  # Center function for banner text
  center() {
    local line="$1"; local w="$width"
    local len=${#line}
    local pad=$(( (w - len) / 2 ))
    [ $pad -lt 0 ] && pad=0
    printf "%s%*s%s%s\n" "$COLOR" "$pad" "" "$line" "$NC"
  }

  # Print top banner (color already set based on total_percent earlier)
  printf "%s%s%s\n" "$COLOR" "$border" "$NC"
  center "UNIT TEST COVERAGE: ${total_percent}%"
  if [ "$total_percent" -eq 100 ]; then center "ALL COVERAGE CHECKS MET!"; else center "COVERAGE CHECKS NOT MET!"; fi
  printf "%s%s%s\n" "$COLOR" "$border" "$NC"

  # Print all output lines
  local WHITE="${ESC}[97m"
  for line in "${output_lines[@]}"; do
    if [[ "$line" == *"Class Name:"* ]]; then
      # Replace empty middle column with "Direct Link To Report:" centered in the URL column
      local url_header="Direct Link To Report:"
      local url_col_width=165
      # Center the header within the URL column width, then add 9 spaces to move right
      local header_len=${#url_header}
      local url_padding=$(( (url_col_width - header_len) / 2 + 9 ))
      local positioned_url_header=$(printf "%*s%s" "$url_padding" "" "$url_header")
      local header_stats=$(printf "%10s | %12s | %12s | %12s" "Tests" "Coverage" "Passing" "Failed")
      local modified_line=$(printf "%-35s %-165s %s" "     Class Name:" "$positioned_url_header" "$header_stats")
      printf "%s%s%s\n" "$WHITE" "$modified_line" "$NC"
    else
      # Apply blue color to URLs in data rows
      echo "$line" | sed -E "s|(https://[^ ]+)|${BLUE}\1${NC}|g"
    fi
  done

  # Print bottom separator matching the width (with same color as top banner)
  printf "%s%s%s\n" "$COLOR" "$border" "$NC"

  # Create HTML index with clickable links to all class coverage reports
  local INDEX_FILE="fargate/target/site/jacoco/class-coverage-index.html"
  cat > "$INDEX_FILE" <<'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Unit Test Coverage - Per Class Links</title>
<style>
body { font-family: monospace; margin: 20px; background: #f5f5f5; }
h1 { color: #333; }
table { border-collapse: collapse; width: 100%; background: white; }
th { background: #4CAF50; color: white; padding: 12px; text-align: left; }
td { padding: 8px; border-bottom: 1px solid #ddd; }
tr:hover { background: #f1f1f1; }
a { color: #1976D2; text-decoration: none; }
a:hover { text-decoration: underline; }
.stats { text-align: right; }
</style>
</head>
<body>
<h1>Unit Test Coverage - Per Class Reports</h1>
<table>
<tr><th>Class Name</th><th>Tests</th><th>Lines</th><th>Coverage</th><th>Report Link</th></tr>
HTMLEOF

  while IFS='|' read -r base link tests lines percent pct_color; do
    local html_path="${link##*/jacoco/}"
    local rel_link="${html_path}"
    cat >> "$INDEX_FILE" <<EOF
<tr>
<td>${base}</td>
<td class="stats">${tests}</td>
<td class="stats">${lines}</td>
<td class="stats">${percent}%</td>
<td><a href="${rel_link}" target="_blank">View Coverage</a></td>
</tr>
EOF
  done < <(sort -f -t '|' -k1,1 "$data_file")

  cat >> "$INDEX_FILE" <<'HTMLEOF'
</table>
</body>
</html>
HTMLEOF

  rm -f "$tmp_classes" "$data_file" || true
}

run_tests
test_exit_code=$?

# Always print coverage report, even if tests failed
print_coverage

# Exit with the original test exit code
exit $test_exit_code
