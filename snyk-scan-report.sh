#!/usr/bin/env python3
"""Unified Snyk scan banner & remediation script supporting dependency (vulnerabilities) and static code (issues).

Modes:
    dependency (default) - expects Snyk dependency scan JSON with 'vulnerabilities'.
    static                - expects Snyk static code analysis JSON with 'issues'.

Invocation:
    python snyk_scan_coverage.py [JSON_PATH]                  (dependency mode)
    python snyk_scan_coverage.py --mode static [STATIC_JSON]  (static mode)

Exit codes:
    0  - No fail-severity findings (pass)
    97 - One or more fail-severity findings (fail)

Environment Variables:
    JSON_OUTPUT / STATIC_JSON_OUTPUT   Input JSON path fallbacks.
    SNYK_FAIL_SEVERITY                 Fail severity (dependency mode) default 'high'.
    SNYK_STATIC_FAIL_SEVERITY          Fail severity (static mode) default 'high'.
    SNYK_MAX_LIST                      Max remediation items (dependency mode) default 10.
    SNYK_STATIC_MAX_LIST               Max remediation items (static mode) default 10.
    # SNYK_BANNER_WIDTH: Banner width in characters (default 120, min 80)
    SNYK_STATIC_BANNER_WIDTH           Width for static banner (default 150, min 80).
    NO_COLOR                           Disable ANSI colors if set.
    SNYK_OUTPUT_BANNER_FILE            Override banner file output (optional).
    SNYK_SHOW_SCOPE                    Show direct/transitive counts if inferable (dependency) when '1'.
    SNYK_SHOW_IGNORED                  Show ignored vulnerability count (dependency) when '1'.
    SNYK_SHOW_TREND                    Show deltas vs previous run (dependency) when '1'.
    SNYK_STATIC_SHOW_CATEGORIES        Show static issue category counts when '1'.
    SNYK_STATIC_SOURCE_PATH            Base source path to count scanned files (static, optional).
    SNYK_SHOW_DEP_BREAKDOWN            When '1' (or unset), show categorized dependency breakdown (dependency mode). Set '0' to disable.
    SNYK_DEP_LIST_PATH                 Path to full dependency list (group:artifact:version per line); optional.
    SNYK_SHOW_DEP_LIST                 When '1' (default if breakdown active), include full per-category dependency listings.
    SNYK_FALLBACK_MAVEN_LIST           Optional explicit path to Maven dependency:list output (e.g. fargate/target/dependency_list.txt).

Notes:
    - Missing/invalid JSON treated as PASS (exit 0) to avoid pipeline noise.
    - Static banner file default: <json_basename>-banner.txt
    - Dependency banner is NOT written to file (console only) unless SNYK_OUTPUT_BANNER_FILE provided.
"""
from __future__ import annotations
import json, sys, os, textwrap, time
import re

def color(code: str) -> str:
    if os.environ.get('NO_COLOR'):
        return ''
    return f"\033[{code}m"

RESET = color('0')
RED = color('31;1')
YELLOW = color('33;1')
GREEN = color('32;1')
CYAN = color('36;1')
MAGENTA = color('35;1')
GRAY = color('90')
WHITE = color('97')

def load_report(path: str):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"{YELLOW}[WARN]{RESET} Unable to read Snyk JSON report '{path}': {e}. Skipping fail check.")
        sys.exit(0)  # treat unreadable file as pass

def extract_highs(data: dict, fail_severity: str):
    vulns = data.get('vulnerabilities', [])
    return [v for v in vulns if v.get('severity') == fail_severity]

def shortest_fixed_version(vuln) -> str:
    fixed = vuln.get('fixedIn') or []
    if not fixed:
        return 'None'
    # fixedIn may contain version ranges; pick the first entry for display
    return fixed[0]

def remediation_snippet(vuln, package_manager: str = 'unknown') -> str:
    pkg = vuln.get('packageName') or 'UNKNOWN'
    fixed = shortest_fixed_version(vuln)
    if fixed == 'None':
        return 'No fixed version published yet. Monitor advisory.'
    
    # Detect package manager from context or package name format
    pkg_mgr = package_manager.lower()
    
    # Python packages (pip)
    if pkg_mgr in ('pip', 'poetry') or (':' not in pkg and not pkg.startswith('com.') and not pkg.startswith('org.')):
        snippet = f"{pkg}=={fixed}"
        return snippet
    
    # Maven packages (pom.xml)
    gid = pkg.split(':')[0] if ':' in pkg else vuln.get('moduleName') or 'GROUP_ID'
    aid = pkg.split(':')[1] if ':' in pkg else pkg
    snippet = f"<dependency>\n  <groupId>{gid}</groupId>\n  <artifactId>{aid}</artifactId>\n  <version>{fixed}</version>\n</dependency>"
    return snippet

def build_counts(vulns):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        sev = (v.get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
    return counts

def compute_scope(vulns, dependency_count):
    """Attempt to derive direct vs transitive counts from vulnerability chains.
    If no vulnerabilities (0), cannot infer direct count; return (None, None)."""
    if not vulns:
        return None, None
    roots = set()
    for v in vulns:
        chain = v.get('from') or []
        if len(chain) >= 1:
            roots.add(chain[0])
    direct = len(roots) if roots else None
    try:
        total = int(dependency_count) if dependency_count not in (None, '') else None
    except ValueError:
        total = None
    transitive = (total - direct) if (direct is not None and total is not None) else None
    return direct, transitive

def count_ignored(vulns):
    ignored = 0
    for v in vulns:
        if isinstance(v.get('isIgnored'), bool) and v['isIgnored']:
            ignored += 1
        elif isinstance(v.get('ignored'), bool) and v['ignored']:
            ignored += 1
    return ignored

def load_previous_metrics(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None

def save_current_metrics(path, counts, dependency_count):
    payload = {
        'timestamp': int(time.time()),
        'counts': counts,
        'dependencyCount': dependency_count
    }
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f)
    except Exception as e:
        print(f"{YELLOW}[WARN]{RESET} Unable to persist trend metrics: {e}")

def format_delta(current, previous):
    diff = current - previous
    if diff == 0:
        return '0'
    sign = '+' if diff > 0 else ''
    return f"{sign}{diff}"

def print_banner_dependency(vulns, fail_severity: str, json_path: str, dependency_count: str, html_report: str | None, package_manager: str, scan_context: str | None, raw_data: dict):
    """Render a unified banner (green if pass, red if fail) with key scan metrics.
    Optionally enrich with scope (direct/transitive), ignored counts, and trend deltas controlled via env vars:
      SNYK_SHOW_SCOPE=1, SNYK_SHOW_IGNORED=1, SNYK_SHOW_TREND=1."""
    counts = build_counts(vulns)
    failing = any(v.get('severity') == fail_severity for v in vulns)
    width = int(os.environ.get('SNYK_BANNER_WIDTH', '120'))
    if width < 80:
        width = 80
    sep = '=' * width

    # Determine status message with optional context
    scan_type = "DEPENDENCY"
    if scan_context:
        # Format: "lambda:module_name" or "fargate:java" -> customize scan type
        if ':' in scan_context:
            parts = scan_context.split(':', 1)
            if parts[0] == 'lambda':
                scan_type = "PYTHON DEPENDENCY"
            elif parts[0] == 'fargate' and parts[1] == 'java':
                scan_type = "JAVA DEPENDENCY"

    if failing:
        status_msg = f"SNYK {scan_type} SCAN VULNERABILITIES FOUND!"
    else:
        status_msg = f"SNYK {scan_type} SCAN"

    color = RED if failing else GREEN
    pad = max(0, (width - len(status_msg)) // 2)

    # Precompute optional enrichment
    show_scope = os.environ.get('SNYK_SHOW_SCOPE') == '1'
    show_ignored = os.environ.get('SNYK_SHOW_IGNORED') == '1'
    show_trend = os.environ.get('SNYK_SHOW_TREND') == '1'
    trend_state_file = os.environ.get('SNYK_TREND_STATE_FILE') or os.path.join(os.path.dirname(json_path) or '.', 'snyk-dep-last-metrics.json')
    prev_metrics = None
    if show_trend:
        prev_metrics = load_previous_metrics(trend_state_file)

    direct = transitive = None
    if show_scope:
        direct, transitive = compute_scope(vulns, dependency_count)

    ignored_count = None
    if show_ignored:
        ignored_count = count_ignored(vulns)

    # Trend deltas
    trend_line = None
    if show_trend:
        if prev_metrics and 'counts' in prev_metrics:
            prev_counts = prev_metrics.get('counts', {})
            tprev = int(prev_metrics.get('dependencyCount') or 0)
            total_now = sum(counts.values())
            total_prev = sum(prev_counts.get(k, 0) for k in ('critical','high','medium','low'))
            deltas = {
                'critical': format_delta(counts['critical'], prev_counts.get('critical', 0)),
                'high': format_delta(counts['high'], prev_counts.get('high', 0)),
                'medium': format_delta(counts['medium'], prev_counts.get('medium', 0)),
                'low': format_delta(counts['low'], prev_counts.get('low', 0)),
                'total': format_delta(total_now, total_prev)
            }
            trend_line = ("Trend (Δ Critical/High/Medium/Low/Total): "
                          f"{deltas['critical']}/{deltas['high']}/{deltas['medium']}/{deltas['low']}/{deltas['total']}")
        else:
            trend_line = 'Trend: (first run - no previous metrics)'

    # Persist current metrics AFTER reading previous so next run can diff
    if show_trend:
        save_current_metrics(trend_state_file, counts, dependency_count)

    def line(txt):
        if len(txt) > width:
            txt = txt[:width-3] + '...'
        return txt + (' ' * (width - len(txt)))

    # Helper for color-coded severity
    def sev_color(sev):
        if sev == 'critical' or sev == 'high':
            return RED
        elif sev == 'medium':
            return YELLOW
        elif sev == 'low':
            return CYAN
        return GREEN

    # Print banner header
    print(f"{color}{sep}")
    print(' ' * pad + status_msg)
    print(sep + RESET)

    # Print centered severity counts (matching static scan format)
    total_vulns = sum(counts.values())
    
    # Calculate clean count: total dependencies minus vulnerabilities
    total_deps = int(dependency_count) if dependency_count and dependency_count.isdigit() else 0
    clean_count = max(0, total_deps - total_vulns) if total_deps > 0 else (0 if total_vulns > 0 else 1)

    # Build severity counts line for width calculation
    sev_counts_line = (
        f"Critical={counts['critical']}  |  "
        f"High={counts['high']}  |  "
        f"Medium={counts['medium']}  |  "
        f"Low={counts['low']}  |  "
        f"Clean={clean_count}"
    )

    # Calculate padding for center alignment
    header_text = "Severity Counts:"
    header_pad = max(0, (width - len(header_text)) // 2)
    counts_pad = max(0, (width - len(sev_counts_line)) // 2)

    print(WHITE + ' ' * header_pad + header_text + RESET)

    # Print centered counts with colors
    sev_summary_colored = (
        f"{sev_color('critical')}Critical={counts['critical']}{RESET}  |  "
        f"{sev_color('high')}High={counts['high']}{RESET}  |  "
        f"{sev_color('medium')}Medium={counts['medium']}{RESET}  |  "
        f"{sev_color('low')}Low={counts['low']}{RESET}  |  "
        f"{GREEN}Clean={clean_count}{RESET}"
    )
    print(' ' * counts_pad + sev_summary_colored)
    print()  # Empty line for spacing after severity counts

    # Don't print closing separator here - table will follow immediately if enabled
    # Optional enrichment sections (only if enabled)
    if show_scope and direct is not None:
        scope_val = f"Direct={direct} Transitive={transitive if transitive is not None else 'n/a'}"
        print(WHITE + line(f"Dependency scope: {scope_val}") + RESET)
    elif show_scope:
        print(WHITE + line('Dependency scope: n/a (no vuln chains to infer)') + RESET)

    # Optional dependency category breakdown (disabled - table format used instead)

    if show_ignored and ignored_count is not None:
        print(WHITE + line(f'Ignored vulnerabilities: {ignored_count}') + RESET)

    if trend_line:
        print(WHITE + line(trend_line) + RESET)

    # Only print closing separator if no table will follow
    # The table will be printed by print_dependency_table if enabled

def print_dependency_table(categories, per_category, vulns, raw_data, width=120):
    """Print a formatted table of dependencies organized by category, similar to mutation test format."""
    if not categories:
        return

    # Build vulnerability lookup by package name for quick severity assignment
    vuln_by_pkg = {}
    for v in vulns:
        pkg = v.get('packageName') or v.get('moduleName') or ''
        if pkg:
            sev = (v.get('severity') or 'unknown').lower()
            if pkg not in vuln_by_pkg or severity_priority(sev) > severity_priority(vuln_by_pkg[pkg]):
                vuln_by_pkg[pkg] = sev

    # Collect all dependencies with their categories and severities
    dep_data = []
    for cat in categories:
        for dep_entry in sorted(per_category[cat]):
            # dep_entry format: group:artifact or group:artifact:version
            parts = dep_entry.split(':')
            if len(parts) < 2:
                continue

            # Try to match vulnerability by checking if package name contains artifact
            artifact = parts[1]
            group = parts[0]
            version = parts[2] if len(parts) > 2 else 'unknown'

            # Look for matching vulnerability
            severity = 'none'
            for pkg_name, pkg_sev in vuln_by_pkg.items():
                if artifact in pkg_name or pkg_name in dep_entry:
                    severity = pkg_sev
                    break

            dep_data.append({
                'category': cat,
                'name': f"{artifact}:{version}",
                'full_name': dep_entry,
                'severity': severity
            })

    if not dep_data:
        return

    # Calculate column widths
    max_name_len = max(len(d['name']) for d in dep_data)
    max_cat_len = max(len(d['category']) for d in dep_data)

    # Build severity summary
    sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'none': 0}
    for d in dep_data:
        sev = d['severity']
        if sev in sev_counts:
            sev_counts[sev] += 1

    # Calculate column widths for display
    max_name_len = max(len(d['name']) for d in dep_data)
    max_cat_len = max(len(d['category']) for d in dep_data)

    # Helper for color-coded severity (used later for individual rows)
    def sev_color(sev):
        if sev == 'critical' or sev == 'high':
            return RED
        elif sev == 'medium':
            return YELLOW
        elif sev == 'low':
            return CYAN
        return GREEN

    # Print invisible centered separator line using black text color (invisible on black terminal background)
    invisible_sep = ' ' * ((width - 1) // 2) + '-' + ' ' * ((width - 1) // 2)
    print(f"\033[30m{invisible_sep}\033[0m")  # \033[30m sets black foreground (invisible on black terminal), \033[0m resets

    # Print column headers with underlines
    h1 = "Dependency Name"
    h2 = "Category"
    h3 = "Severity"

    # Column widths that fit within banner width (120 chars total)
    # Format: name(50) + spaces(2) + category(42) + spaces(2) + severity(22) = 120
    name_width = 50
    cat_width = 42
    sev_width = 22

    # Individual padding controls - adjust these values to align columns as desired
    name_padding = 0   # Left padding for Dependency Name column
    cat_padding = 6    # Left padding for Category column
    sev_padding = 10   # Left padding for Severity column

    name_header = ' ' * name_padding + h1
    cat_header = ' ' * cat_padding + h2
    sev_header = ' ' * sev_padding + h3

    header_line = f"{name_header:<{name_width}}  {cat_header:<{cat_width}}  {sev_header}"
    underline = f"{' ' * name_padding}{'-' * len(h1):<{name_width - name_padding}}  {' ' * cat_padding}{'-' * len(h2):<{cat_width - cat_padding}}  {' ' * sev_padding}{'-' * len(h3)}"
    print(header_line)
    print(underline)

    # Print dependencies grouped by category (no blank lines between categories)
    for d in dep_data:
        name_col = d['name']
        cat_col = d['category']
        sev_col = d['severity'].upper() if d['severity'] != 'none' else 'CLEAN'
        sev_colored = f"{sev_color(d['severity'])}{sev_col}{RESET}"

        # Apply individual padding to match headers
        name_display = ' ' * name_padding + name_col
        cat_display = ' ' * cat_padding + cat_col
        # For severity, apply padding without color codes for proper alignment
        sev_plain = ' ' * sev_padding + sev_col

        # Use fixed column widths matching header (color severity text separately)
        print(f"{name_display:<{name_width}}  {cat_display:<{cat_width}}  {sev_color(d['severity'])}{sev_plain}{RESET}")

    # Print closing separator line (use color based on severity state)
    # Check if all dependencies are clean (no vulnerabilities)
    has_vulns = any(d['severity'] != 'none' for d in dep_data)
    sep_color = RED if has_vulns else GREEN
    sep_line = '=' * width
    print(sep_color + sep_line + RESET)

def severity_priority(sev):
    """Return priority level for severity comparison (higher = more severe)."""
    priority = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'none': 0, 'unknown': 0}
    return priority.get(sev.lower(), 0)

def print_summary_dependency(failing_vulns, fail_severity: str, max_list: int, package_manager: str = 'unknown'):
    if not failing_vulns:
        return
    # Deduplicate by vulnerability ID to avoid showing same vuln multiple times (one per path)
    seen_ids = set()
    unique_vulns = []
    for v in failing_vulns:
        vid = v.get('id')
        if vid and vid not in seen_ids:
            seen_ids.add(vid)
            unique_vulns.append(v)

    if not unique_vulns:
        return

    # Group vulnerabilities by package name for consolidated remediation
    by_package = {}
    for v in unique_vulns:
        pkg = v.get('packageName') or v.get('moduleName') or 'UNKNOWN'
        if pkg not in by_package:
            by_package[pkg] = []
        by_package[pkg].append(v)

    # Detect package manager type
    pkg_mgr = package_manager.lower()
    is_python = pkg_mgr in ('pip', 'poetry')
    is_maven = pkg_mgr in ('maven', 'gradle') or ':' in next(iter(by_package.keys()), '')

    print("")
    print(f"Remediation details for {fail_severity} severity vulnerabilities ({len(unique_vulns)} unique issues, {len(failing_vulns)} total paths):")
    print("")
    
    count = 0
    for pkg, vulns in sorted(by_package.items()):
        if count >= max_list:
            break
        count += 1
        
        # Get common fix version (should be same for all vulns in this package)
        first_vuln = vulns[0]
        version = first_vuln.get('version') or 'UNKNOWN'
        fixed = first_vuln.get('fixedIn') or []
        fixed_version = fixed[0] if fixed else 'None'
        
        print(f"{RED}Package: {pkg} (Current: {version} → Fix: {fixed_version}){RESET}")
        print(f"   Affected by {len(vulns)} vulnerabilit{'y' if len(vulns) == 1 else 'ies'}:")
        
        # List all vulnerabilities affecting this package
        for v in vulns:
            vid = v.get('id')
            title = v.get('title')
            url = f"https://security.snyk.io/vuln/{vid}" if vid else 'N/A'
            print(f"     • {title}")
            print(f"       ID: {vid}")
            print(f"       Advisory: {url}")
        
        # Provide single fix instruction for the package
        if fixed_version != 'None':
            print("")
            if is_python or (not is_maven and ':' not in pkg):
                print(f"   {MAGENTA}Fix: Update requirements.txt or run:{RESET}")
                print(f"   {MAGENTA}   pip install {pkg}=={fixed_version}{RESET}")
            else:
                print(f"   {MAGENTA}Fix: Update pom.xml (Maven) or build.gradle (Gradle):{RESET}")
                snippet = remediation_snippet(first_vuln, package_manager)
                wrapped = textwrap.indent(snippet, '      ')
                print(f"{MAGENTA}{wrapped}{RESET}")
        else:
            print(f"   {YELLOW}No fixed version available yet. Monitor advisories.{RESET}")
        
        print("")
    
    if len(by_package) > max_list:
        print(f"{GRAY}... and {len(by_package) - max_list} more package(s). See full report for details.{RESET}")
        print("")
    
    print(f"{CYAN}Full JSON details: {os.environ.get('JSON_OUTPUT', 'snyk-dependency-scan.json')}{RESET}")

def collect_static_issues(data: dict):
    """Return a normalized list of static issues from multiple possible Snyk Code JSON formats.
    Supported structures (observed across CLI versions):
      - Top-level 'issues': current canonical list.
      - Top-level 'vulnerabilities': legacy fallback.
      - Top-level 'codeAnalysisIssues': alternate naming.
      - SARIF style: 'runs' -> [{ results: [...]}]. We map SARIF results into internal issue dicts.
    Each normalized issue dict will expose at minimum: title, id, severity, locations.
    """
    # Debug: show available top-level keys if SNYK_STATIC_DEBUG enabled
    if os.environ.get('SNYK_STATIC_DEBUG') == '1':
        print(f"{GRAY}[DEBUG] JSON top-level keys: {', '.join(sorted(data.keys()))}{RESET}", file=sys.stderr)

    # 1. Canonical
    issues = data.get('issues')
    if isinstance(issues, list) and issues:
        return issues
    # 2. Legacy vulnerabilities key
    vulns = data.get('vulnerabilities')
    if isinstance(vulns, list) and vulns:
        return vulns
    # 3. Alternate key
    alt = data.get('codeAnalysisIssues')
    if isinstance(alt, list) and alt:
        return alt
    # 4. SARIF structure
    sarif_runs = data.get('runs')
    normalized = []
    if isinstance(sarif_runs, list):
        for run in sarif_runs:
            results = run.get('results') or []
            if not isinstance(results, list):
                continue
            for res in results:
                msg = (res.get('message') or {}).get('text') if isinstance(res.get('message'), dict) else res.get('message')
                rule_id = res.get('ruleId') or res.get('id')
                # Severity may live in properties.severity or level
                sev = None
                props = res.get('properties') or {}
                if isinstance(props, dict):
                    sev = props.get('severity') or props.get('priority')
                sev = sev or res.get('level') or 'info'
                # Map SARIF levels to Snyk severity (note->low, warning->medium, error->high)
                sev_lower = str(sev).lower()
                if sev_lower == 'note':
                    sev = 'low'
                elif sev_lower == 'warning':
                    sev = 'medium'
                elif sev_lower == 'error':
                    sev = 'high'
                else:
                    sev = sev_lower
                # Locations mapping
                locs_raw = res.get('locations') or []
                locs_norm = []
                if isinstance(locs_raw, list):
                    for loc in locs_raw:
                        if not isinstance(loc, dict):
                            continue
                        phys = loc.get('physicalLocation') or {}
                        if not isinstance(phys, dict):
                            continue
                        artifact_loc = phys.get('artifactLocation') or {}
                        region = phys.get('region') or {}
                        path = artifact_loc.get('uri') or artifact_loc.get('path') or ''
                        start_line = region.get('startLine') or region.get('line')
                        locs_norm.append({'file': path, 'line': start_line})
                normalized.append({
                    'title': msg or rule_id or 'Untitled',
                    'id': rule_id or 'N/A',
                    'severity': str(sev).lower(),
                    'locations': locs_norm
                })
        if normalized:
            return normalized
    return []

def severity_counts(issues):
    counts = { 'critical':0, 'high':0, 'medium':0, 'low':0 }
    for i in issues:
        sev = (i.get('severity') or '').lower()
        if sev in counts:
            counts[sev] += 1
    return counts

def is_ignored(issue):
    if isinstance(issue.get('isIgnored'), bool):
        return issue['isIgnored']
    if isinstance(issue.get('ignored'), bool):
        return issue['ignored']
    return False

def format_static_location(issue):
    locs = issue.get('locations') or issue.get('references') or []
    if locs and isinstance(locs, list):
        first = locs[0]
        path = first.get('file') or first.get('path') or ''
        line = first.get('line') or first.get('startLine') or ''
        if path:
            return f"{path}{':' + str(line) if line else ''}".strip(':')
    return issue.get('path', '') or 'N/A'

def banner_static(issues, fail_sev: str, json_path: str, width: int, scan_context: str | None, show_categories: bool):
    counts = severity_counts(issues)
    open_issues = [i for i in issues if not is_ignored(i)]
    ignored_issues = [i for i in issues if is_ignored(i)]

    # Auto-calculate width based on longest issue description if issues exist
    if open_issues:
        max_title_len = max(len(issue.get('title') or issue.get('id') or 'Untitled') for issue in open_issues)
        max_location_len = max(50, max(len(f"{(issue.get('locations') or [{}])[0].get('file', '').split('/')[-1]}:{(issue.get('locations') or [{}])[0].get('line', '')}") for issue in open_issues if issue.get('locations')))
        # Calculate needed width: location + description + severity + padding
        calculated_width = max_location_len + max_title_len + 20 + 6  # 20 for severity, 6 for spacing
        width = max(width, calculated_width, 110)  # Use larger of provided width or calculated width, minimum 110

    # Reduce width by 13 characters as requested (7 + 6 additional)
    width = max(80, width - 13)

    # Banner is red only if high or critical issues exist, otherwise green
    any_open = len(open_issues) > 0
    has_high_or_critical = any((i.get('severity') or '').lower() in ('high', 'critical') for i in open_issues)
    severity_gate_fail = any((i.get('severity') or '').lower() == fail_sev for i in open_issues)
    sep = '=' * width
    if any_open:
        status = 'SNYK STATIC SCAN VULNERABILITIES FOUND!'
    else:
        status = 'SNYK STATIC SCAN CLEAN'
    pad = max(0, (width - len(status)) // 2)
    color = RED if has_high_or_critical else GREEN
    def line(txt):
        if len(txt) > width:
            txt = txt[:width-3] + '...'
        return txt + (' ' * (width - len(txt)))
    lines = []
    lines.append(f"{color}{sep}")
    lines.append(' ' * pad + status)
    lines.append(sep)

    # Color-coded severity counts matching dependency scan format
    def sev_color(sev):
        if sev == 'critical' or sev == 'high':
            return RED
        elif sev == 'medium':
            return YELLOW
        elif sev == 'low':
            return CYAN
        return GREEN

    total_issues = sum(counts.values())
    clean_count = len([i for i in issues if not is_ignored(i)]) if total_issues == 0 else 0

    # Build severity counts line (without colors for width calculation)
    sev_counts_line = (
        f"Critical={counts['critical']}  |  "
        f"High={counts['high']}  |  "
        f"Medium={counts['medium']}  |  "
        f"Low={counts['low']}  |  "
        f"Clean={clean_count if total_issues == 0 else 0}"
    )

    # Calculate padding for center alignment
    header_text = "Severity Counts:"
    header_pad = max(0, (width - len(header_text)) // 2)
    counts_pad = max(0, (width - len(sev_counts_line)) // 2)

    lines.append('')
    lines.append(WHITE + ' ' * header_pad + header_text + RESET)

    # Print centered counts with colors
    sev_summary_colored = (
        f"{sev_color('critical')}Critical={counts['critical']}{RESET}  |  "
        f"{sev_color('high')}High={counts['high']}{RESET}  |  "
        f"{sev_color('medium')}Medium={counts['medium']}{RESET}  |  "
        f"{sev_color('low')}Low={counts['low']}{RESET}  |  "
        f"{GREEN}Clean={clean_count if total_issues == 0 else 0}{RESET}"
    )
    lines.append(' ' * counts_pad + sev_summary_colored)
    lines.append("")  # Blank line after severity counts

    # List each finding with location first, then description, then severity
    if open_issues:
        # Print invisible centered separator line using black text color (invisible on black terminal background)
        invisible_sep = ' ' * ((width - 1) // 2) + '-' + ' ' * ((width - 1) // 2)
        lines.append(f"\033[30m{invisible_sep}\033[0m")  # \033[30m sets black foreground, \033[0m resets

        # Print column headers with underlines
        h1 = "Location"
        h2 = "Issue Description"
        h3 = "Severity"

        # Calculate column widths with right-aligned severity column
        # Fixed severity width at the end, location takes 15%, description fills remaining space
        sev_width = 10  # Fixed width for severity column
        loc_width = max(45, int(width * 0.15))
        desc_width = width - loc_width - sev_width - 4  # 4 spaces for separators

        # Individual padding controls
        loc_padding = 0
        desc_padding = 0

        # Build headers with padding
        loc_header = ' ' * loc_padding + h1
        desc_header = ' ' * desc_padding + h2
        # Right-align severity header within its column
        sev_header = h3.rjust(sev_width)

        header_line = f"{loc_header:<{loc_width}}  {desc_header:<{desc_width}}  {sev_header}"
        underline = f"{' ' * loc_padding}{'-' * len(h1):<{loc_width - loc_padding}}  {' ' * desc_padding}{'-' * len(h2):<{desc_width - desc_padding}}  {'-' * len(h3):>{sev_width}}"
        lines.append(WHITE + header_line + RESET)
        lines.append(WHITE + underline + RESET)

        for issue in open_issues:
            title = issue.get('title') or issue.get('id') or 'Untitled'
            sev = (issue.get('severity') or 'unknown').lower()
            sev_display = sev.upper()

            # Extract location details
            locs = issue.get('locations') or issue.get('references') or []
            if locs and isinstance(locs, list):
                first = locs[0]
                file_path = first.get('file') or first.get('path') or 'Unknown'
                line_num = first.get('line') or first.get('startLine') or 'Unknown'

                # Extract just the class name from the full path
                if '/' in file_path:
                    class_name = file_path.split('/')[-1]
                else:
                    class_name = file_path
            else:
                class_name = 'Unknown'
                line_num = 'Unknown'

            location = f"{class_name}:{line_num}"
            # Truncate location if needed
            if len(location) > loc_width:
                location = location[:loc_width-3] + '...'

            # Truncate description if needed to fit column width
            if len(title) > desc_width:
                title = title[:desc_width-3] + '...'

            # Apply padding to match headers
            loc_display = ' ' * loc_padding + location
            desc_display = ' ' * desc_padding + title

            # Right-align severity within its column by padding left side
            sev_padding_needed = sev_width - len(sev_display)
            sev_with_left_pad = ' ' * sev_padding_needed + sev_display

            # Format line with fixed column widths (apply color to severity only)
            issue_line = f"{WHITE}{loc_display:<{loc_width}}  {desc_display:<{desc_width}}  {sev_color(sev)}{sev_with_left_pad}{RESET}"
            lines.append(issue_line)

        lines.append("")  # Blank line after issues

    lines.append(color + sep + RESET)
    return lines

def remediation_static(issues, fail_sev: str, max_list: int, width: int):
    failing_issues = [i for i in issues if (i.get('severity') or '').lower() == fail_sev and not is_ignored(i)]
    if not failing_issues:
        return []
    out = []
    out.append("")
    out.append(f"Remediation details (top {min(len(failing_issues), max_list)}) for severity '{fail_sev}':")
    for issue in failing_issues[:max_list]:
        title = issue.get('title') or issue.get('id') or 'Untitled'
        iid = issue.get('id') or 'N/A'
        sev = issue.get('severity') or 'N/A'
        loc = format_static_location(issue)
        out.append(f"{RED} - {title}{RESET}")
        out.append(f"   ID: {iid}")
        out.append(f"   Severity: {sev}")
        out.append(f"   Location: {loc}")
        advice = issue.get('msg') or issue.get('description') or 'Review code and apply recommended security best practices.'
        wrapped = textwrap.fill(advice, width=width - 6)
        out.append(f"   Advice: {wrapped}")
        out.append("   Next Steps: Refactor / sanitize and re-run pipeline.")
        out.append("")
    return out

def classify_static_issue(title: str) -> str:
    if not title:
        return 'other'
    t = title.lower()
    mapping = [
        ('injection', 'injection'),
        ('sql', 'injection'),
        ('xss', 'xss'),
        ('cross-site', 'xss'),
        ('deserial', 'deserialization'),
        ('crypto', 'cryptography'),
        ('cryptograph', 'cryptography'),
        ('path traversal', 'path-traversal'),
        ('directory traversal', 'path-traversal'),
        ('hardcoded secret', 'secret'),
        ('secret', 'secret'),
        ('insecure config', 'insecure-config'),
        ('configuration', 'insecure-config'),
        ('race condition', 'race-condition'),
        ('command injection', 'injection'),
    ]
    for needle, cat in mapping:
        if needle in t:
            return cat
    return 'other'

def static_category_counts(issues):
    counts = {}
    for i in issues:
        title = i.get('title') or i.get('id') or ''
        cat = classify_static_issue(title)
        counts[cat] = counts.get(cat, 0) + 1
    # Order: injection, xss, deserialization, cryptography, path-traversal, secret, insecure-config, race-condition, other
    order = ['injection','xss','deserialization','cryptography','path-traversal','secret','insecure-config','race-condition','other']
    return [(c, counts.get(c, 0)) for c in order if counts.get(c,0) > 0]

################ Dependency Breakdown Helpers ################
CAT_RULES = [
    # Java / General
    ('AWS', re.compile(r'(^com\.amazonaws|aws|amazon|software\.amazon|boto3|botocore)', re.I)),
    ('SPRING', re.compile(r'(^org\.springframework|spring-)', re.I)),
    ('JACKSON', re.compile(r'(jackson)', re.I)),
    ('APACHE', re.compile(r'(^org\.apache|apache-)', re.I)),
    ('LOGGING', re.compile(r'(log4j|slf4j|logback|logging)', re.I)),
    ('DATABASE', re.compile(r'(postgres|mysql|jdbc|hibernate|flyway|sqlalchemy|psycopg2|pymysql)', re.I)),
    ('WEB', re.compile(r'(flask|django|fastapi|requests|urllib3)', re.I)),
    ('SECURITY', re.compile(r'(jwt|oauth|security|crypto|cryptography|pyopenssl)', re.I)),
    ('DATA', re.compile(r'(pandas|numpy|scipy|pyarrow)', re.I)),
    ('TEST', re.compile(r'(junit|mockito|assertj|hamcrest|pytest)', re.I)),
    ('UTIL', re.compile(r'(commons-|guava|lombok|util|json|gson|yaml|jinja2|dateutil)', re.I)),
]

def categorize_dependency(group: str, artifact: str) -> str:
    combined = f"{group}:{artifact}".lower()
    for cat, regex in CAT_RULES:
        if regex.search(combined):
            return cat
    return 'OTHER'

def parse_dependency_line(line: str):
    # Accept formats: group:artifact:version or group:artifact or artifact:version
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    parts = line.split(':')
    if len(parts) >= 2:
        group = parts[0]
        artifact = parts[1]
        return group, artifact
    return None

def extract_dependencies_from_json(data: dict):
    deps = set()
    # Vulnerability chains 'from'
    for v in data.get('vulnerabilities', []) or []:
        chain = v.get('from') or []
        for item in chain:
            base = item.split('@')[0]
            if ':' in base:
                deps.add(base.split('@')[0])
            else:
                deps.add(f"{base}:{base}")
    # packages list (if available)
    for p in data.get('packages', []) or []:
        name = p.get('name') or ''
        if not name:
            continue
        base = name.split('@')[0]
        if ':' in base:
            deps.add(base.split('@')[0])
        else:
            deps.add(f"{base}:{base}")
    return sorted(deps)

def extract_dependencies_from_graph(data: dict):
    graph = data.get('dependencyGraph') or {}
    pkgs = graph.get('pkgs') or []
    deps = set()
    for p in pkgs:
        pid = p.get('id') or ''  # format name@version
        if not pid:
            continue
        base, _, version = pid.partition('@')
        # For Python we only have package name; replicate as group:artifact using same base
        group = base
        artifact = base
        entry = f"{group}:{artifact}:{version}" if version else f"{group}:{artifact}"
        deps.add(entry)
    return deps

def parse_pip_requirements(path: str):
    deps = set()
    if not os.path.isfile(path):
        return deps
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                raw = line.strip()
                if not raw or raw.startswith('#'):
                    continue
                # Accept forms: name==version, name>=version, name<=version, name~=version, name
                # Version can include: digits, dots, hyphens, plus, and post/dev/rc suffixes
                m = re.match(r'([A-Za-z0-9_.\-]+)(==|>=|<=|~=)?([A-Za-z0-9_.\-+]+)?', raw)
                if not m:
                    continue
                name = m.group(1)
                # For pip freeze, always use the version after == operator
                version = m.group(3) if m.group(2) else ''
                group = name
                artifact = name
                entry = f"{group}:{artifact}:{version}" if version else f"{group}:{artifact}"
                deps.add(entry)
    except Exception:
        return deps
    return deps

def parse_maven_dependency_list(path: str):
    deps = set()
    if not os.path.isfile(path):
        return deps
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Typical formats:
                # groupId:artifactId:jar:version:scope (5 parts)
                # groupId:artifactId:packaging:version:scope (5 parts)
                # groupId:artifactId:version (3 parts - sometimes)
                if not line:
                    continue
                # Strip leading [INFO] prefix from Maven output
                if line.startswith('[INFO]'):
                    line = line.replace('[INFO]', '').strip()
                if line.count(':') < 2:
                    continue
                parts = line.split(':')
                group = parts[0].strip()
                artifact = parts[1].strip()
                version = None

                # Parse version based on number of parts
                if len(parts) == 3:
                    # Format: group:artifact:version
                    version = parts[2].strip()
                elif len(parts) >= 5:
                    # Format: group:artifact:packaging:version:scope
                    # Version is at index 3 (4th position)
                    version = parts[3].strip()
                elif len(parts) == 4:
                    # Could be group:artifact:packaging:version or group:artifact:version:scope
                    # Check if part 2 looks like a packaging type (jar, war, pom, etc.)
                    potential_packaging = parts[2].strip().lower()
                    if potential_packaging in ('jar', 'war', 'pom', 'bundle', 'maven-plugin', 'ear'):
                        version = parts[3].strip()
                    else:
                        # Assume it's group:artifact:version:scope
                        version = parts[2].strip()

                if group and artifact:
                    if version:
                        deps.add(f"{group}:{artifact}:{version}")
                    else:
                        # Fallback if we couldn't parse version
                        deps.add(f"{group}:{artifact}")
    except Exception:
        return deps
    return deps

def build_dependency_categories(path: str, data: dict):
    per_category = {}
    explicit_deps = set()
    if os.path.isfile(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for raw in f:
                    raw = raw.strip()
                    if not raw or raw.startswith('#'): continue
                    parts = raw.split(':')
                    if len(parts) >= 2:
                        # Preserve version if present (3rd part)
                        entry = ':'.join(parts[:3])
                        explicit_deps.add(entry)
        except Exception:
            explicit_deps = set()
    # Maven fallback
    fallback_maven_path = os.environ.get('SNYK_FALLBACK_MAVEN_LIST') or 'fargate/target/dependency_list.txt'
    if not os.path.isfile(fallback_maven_path):
        project_root = os.environ.get('CI_PROJECT_DIR')
        if project_root:
            candidate = os.path.join(project_root, fallback_maven_path.lstrip('/'))
            if os.path.isfile(candidate):
                fallback_maven_path = candidate
    maven_deps = parse_maven_dependency_list(fallback_maven_path) if not explicit_deps else set()
    # Jar libs (fat jar)
    jar_libs_file = os.environ.get('SNYK_JAR_LIBS_PATH') or 'fargate/target/jar_libs/libs.txt'
    if not os.path.isfile(jar_libs_file):
        project_root = os.environ.get('CI_PROJECT_DIR')
        if project_root:
            candidate = os.path.join(project_root, jar_libs_file.lstrip('/'))
            if os.path.isfile(candidate):
                jar_libs_file = candidate
    jar_lib_deps = set()
    if not explicit_deps and not maven_deps and os.path.isfile(jar_libs_file):
        try:
            with open(jar_libs_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line=line.strip()
                    if not line.endswith('.jar'): continue
                    base=line[:-4]
                    parts=base.split('-')
                    if len(parts) >= 3:
                        group=parts[0]; artifact='-'.join(parts[1:-1]); version=parts[-1]
                        jar_lib_deps.add(f"{group}:{artifact}:{version}")
        except Exception:
            pass
    # For Python: try py_requirements_full.txt (pip freeze output) first - most complete source
    pip_req_path = os.environ.get('SNYK_PIP_REQUIREMENTS_PATH') or 'lambdas/layer/py_requirements_full.txt'
    if not os.path.isfile(pip_req_path):
        # Try alternate lambda-specific path (e.g., lambdas/cloudwatch_ecs_tagger/py_requirements_full.txt)
        alt_path = os.environ.get('SNYK_PIP_REQUIREMENTS_PATH') or 'lambdas/cloudwatch_ecs_tagger/py_requirements_full.txt'
        if os.path.isfile(alt_path):
            pip_req_path = alt_path
        else:
            # Check in CI project dir
            project_root = os.environ.get('CI_PROJECT_DIR')
            if project_root:
                for candidate_name in ['py_requirements_full.txt', 'requirements.txt']:
                    candidate = os.path.join(project_root, pip_req_path.replace('requirements.txt', candidate_name).lstrip('/'))
                    if os.path.isfile(candidate):
                        pip_req_path = candidate
                        break
    pip_deps = parse_pip_requirements(pip_req_path) if not (explicit_deps or maven_deps or jar_lib_deps) else set()

    # dependencyGraph fallback for Python (may only contain scanned packages, not all installed)
    graph_deps = extract_dependencies_from_graph(data) if not (explicit_deps or maven_deps or jar_lib_deps or pip_deps) else set()

    # JSON-derived deps (chains/packages) - last resort
    json_deps = set(extract_dependencies_from_json(data)) if not (explicit_deps or maven_deps or jar_lib_deps or graph_deps or pip_deps) else set()

    all_deps = explicit_deps or maven_deps or jar_lib_deps or pip_deps or graph_deps or json_deps
    if not all_deps:
        return [], {}
    for entry in all_deps:
        # entry formats: group:artifact or group:artifact:version
        parts = entry.split(':')
        if len(parts) < 2:
            continue
        group = parts[0]
        artifact = parts[1]
        cat = categorize_dependency(group, artifact)
        per_category.setdefault(cat, set()).add(entry)
    categories = sorted(per_category.keys())
    for c in categories:
        per_category[c] = set(sorted(per_category[c], key=lambda x: x.lower()))
    return categories, per_category

def main(argv):
    # Detect mode
    mode = 'dependency'
    json_arg_index = 1
    if len(argv) > 1 and argv[1] == '--mode':
        if len(argv) < 3:
            print(f"{RED}[ERROR]{RESET} --mode provided without value (dependency|static)")
            sys.exit(0)
        mode = argv[2].lower()
        json_arg_index = 3
    if mode not in ('dependency', 'static'):
        print(f"{YELLOW}[WARN]{RESET} Unknown mode '{mode}', defaulting to dependency")
        mode = 'dependency'

    if mode == 'dependency':
        fail_severity = os.environ.get('SNYK_FAIL_SEVERITY', 'high').lower()
        max_list = int(os.environ.get('SNYK_MAX_LIST', '10'))
        path = argv[json_arg_index] if len(argv) > json_arg_index else os.environ.get('JSON_OUTPUT', 'snyk-dependency-scan.json')
        # Basic path traversal mitigation: ensure path stays within project root if defined
        project_root = os.environ.get('CI_PROJECT_DIR') or os.getcwd()
        abs_project_root = os.path.abspath(project_root)
        abs_path = os.path.abspath(path)
        if not abs_path.startswith(abs_project_root):
            print(f"{YELLOW}[WARN]{RESET} Dependency JSON path outside project root denied: {abs_path}")
            sys.exit(0)
        data = load_report(path)
        vulns = data.get('vulnerabilities', [])
        failing_vulns = extract_highs(data, fail_severity)
        dependency_count = str(data.get('dependencyCount', '')) if isinstance(data.get('dependencyCount', ''), (int, str)) else ''
        html_report = None
        json_output_name = os.path.basename(path)
        if json_output_name:
            html_candidate = os.path.join(os.path.dirname(path), os.path.splitext(json_output_name)[0] + '.html')
            if os.path.exists(html_candidate):
                html_report = html_candidate
        package_manager = data.get('packageManager') or 'unknown'
        scan_context = os.environ.get('SNYK_SCAN_CONTEXT')

        # Pre-calculate dependency table data to get accurate count for banner
        categories = []
        per_category = {}
        show_dep_table = os.environ.get('SNYK_SHOW_DEP_TABLE', '0') == '1'
        if show_dep_table:
            show_breakdown_env = os.environ.get('SNYK_SHOW_DEP_BREAKDOWN')
            show_breakdown = (show_breakdown_env != '0')
            if show_breakdown:
                dep_list_path = os.environ.get('SNYK_DEP_LIST_PATH') or os.path.join(os.path.dirname(path) or '.', 'dependencies.txt')
                categories, per_category = build_dependency_categories(dep_list_path, data)

        # Calculate actual dependency count from parsed table data if available
        if categories and per_category:
            actual_dep_count = sum(len(deps) for deps in per_category.values())
            dependency_count = str(actual_dep_count)

        print_banner_dependency(vulns, fail_severity, path, dependency_count, html_report, package_manager, scan_context, data)

        # Print dependency table if we have data
        if categories and per_category:
            table_width = int(os.environ.get('SNYK_BANNER_WIDTH', '120'))
            if table_width < 80:
                table_width = 120
            print_dependency_table(categories, per_category, vulns, data, table_width)

        print_summary_dependency(failing_vulns, fail_severity, max_list, package_manager)
        # Optional banner file output
        banner_file_override = os.environ.get('SNYK_OUTPUT_BANNER_FILE')
        if banner_file_override:
            try:
                with open(banner_file_override, 'w', encoding='utf-8') as bf:
                    # Recreate minimal banner lines for file (without remediation unless failing)
                    bf.write(f"Mode: dependency\n")
            except Exception as e:
                print(f"{YELLOW}[WARN]{RESET} Unable to write banner override file: {e}")
        if failing_vulns:
            print(f"{RED}Failing job!{RESET}")
            sys.exit(97)
        sys.exit(0)
    else:  # static mode
        fail_sev = os.environ.get('SNYK_STATIC_FAIL_SEVERITY', 'high').lower()
        max_list = int(os.environ.get('SNYK_STATIC_MAX_LIST', '10'))
        path = argv[json_arg_index] if len(argv) > json_arg_index else os.environ.get('STATIC_JSON_OUTPUT', 'reports/snyk/fargate/snyk-static-code-scan.json')
        width = int(os.environ.get('SNYK_STATIC_BANNER_WIDTH', '450'))
        if width < 80:
            width = 80
        project_root = os.environ.get('CI_PROJECT_DIR') or os.getcwd()
        abs_project_root = os.path.abspath(project_root)
        abs_path = os.path.abspath(path)
        if not abs_path.startswith(abs_project_root):
            print(f"{YELLOW}[WARN]{RESET} Static JSON path outside project root denied: {abs_path}")
            sys.exit(0)
        data = load_report(path)
        issues = collect_static_issues(data)
        # Optional debug when zero issues parsed but keys exist
        if not issues and os.environ.get('SNYK_STATIC_DEBUG') == '1':
            print(f"{YELLOW}[WARN]{RESET} Parsed zero static issues. Top-level keys: {', '.join(sorted(data.keys()))}")
            # show a hint about enabling SARIF or alternate output
            print(f"{GRAY}Hint: If Snyk CLI updated format, ensure script supports new keys or use --sarif for consistent schema.{RESET}")
        scan_context = os.environ.get('SNYK_SCAN_CONTEXT')
        show_categories = os.environ.get('SNYK_STATIC_SHOW_CATEGORIES') == '1'
        banner_lines = banner_static(issues, fail_sev, path, width, scan_context, show_categories)
        # Source file count (approximate) if provided
        src_path = os.environ.get('SNYK_STATIC_SOURCE_PATH')
        if src_path and os.path.isdir(src_path):
            file_count = 0
            for root, _, files in os.walk(src_path):
                for f in files:
                    if f.endswith(('.java','.kt','.py','.js','.ts','.go','.rb')):
                        file_count += 1
            # Insert before closing separator (second to last index)
            banner_lines.insert(-1, WHITE + (f"Source files scanned (approx): {file_count}").ljust(width) + RESET)
        remediation_lines = remediation_static(issues, fail_sev, max_list, width)
        for ln in banner_lines:
            print(ln)
        for ln in remediation_lines:
            print(ln)
        # Write banner file
        banner_file = os.environ.get('SNYK_OUTPUT_BANNER_FILE') or (os.path.splitext(path)[0] + '-banner.txt')
        try:
            with open(banner_file, 'w', encoding='utf-8') as bf:
                for ln in banner_lines + remediation_lines:
                    bf.write(ln + '\n')
        except Exception as e:
            print(f"{YELLOW}[WARN]{RESET} Unable to write static banner file '{banner_file}': {e}")
        failing_open = any((i.get('severity') or '').lower() == fail_sev and not is_ignored(i) for i in issues)
        if failing_open:
            print(f"{RED}Failing job due to {fail_sev} severity static issues.{RESET}")
            sys.exit(97)
        sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)
