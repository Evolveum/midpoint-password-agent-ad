#!/usr/bin/env bash
# nuget-tree.sh — Parse project.assets.json and print dependency tree
# Usage: ./nuget-tree.sh [path/to/project.assets.json] [options]
#
# Options:
#   -d, --direct-only     Show only direct dependencies and their children
#   -s, --search <name>   Filter tree to packages matching name
#   -r, --reverse <name>  Show what pulls in a specific package
#   -f, --flat            Flat list with "required by" info (no tree)
#   -h, --help            Show this help

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  BOLD='\033[1m'
  DIM='\033[2m'
  GREEN='\033[38;5;86m'
  PURPLE='\033[38;5;141m'
  YELLOW='\033[38;5;226m'
  CYAN='\033[38;5;117m'
  RED='\033[38;5;203m'
  RESET='\033[0m'
else
  BOLD='' DIM='' GREEN='' PURPLE='' YELLOW='' CYAN='' RED='' RESET=''
fi

# ── Defaults ──────────────────────────────────────────────────────────────────
ASSETS_FILE="obj/project.assets.json"
DIRECT_ONLY=false
SEARCH=""
REVERSE=""
FLAT=false

# ── Help ──────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
${BOLD}nuget-tree${RESET} — NuGet dependency tree from project.assets.json

${BOLD}USAGE${RESET}
  $0 [assets-file] [options]

${BOLD}OPTIONS${RESET}
  -d, --direct-only       Show only direct deps and their immediate children
  -s, --search <name>     Filter: only show packages matching <name>
  -r, --reverse <name>    Show which packages pull in <name>
  -f, --flat              Flat list mode: each transitive pkg shows who needs it
  -h, --help              This help

${BOLD}EXAMPLES${RESET}
  $0
  $0 obj/project.assets.json
  $0 -r Newtonsoft.Json
  $0 -s Microsoft.Extensions
  $0 --flat
EOF
  exit 0
}

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)        usage ;;
    -d|--direct-only) DIRECT_ONLY=true; shift ;;
    -f|--flat)        FLAT=true; shift ;;
    -s|--search)      SEARCH="$2"; shift 2 ;;
    -r|--reverse)     REVERSE="$2"; shift 2 ;;
    -*)               echo "Unknown option: $1"; usage ;;
    *)                ASSETS_FILE="$1"; shift ;;
  esac
done

# ── Checks ────────────────────────────────────────────────────────────────────
if [[ ! -f "$ASSETS_FILE" ]]; then
  echo -e "${RED}Error:${RESET} File not found: ${BOLD}$ASSETS_FILE${RESET}"
  echo -e "  Run ${CYAN}dotnet restore${RESET} first, then try again."
  echo -e "  Usage: $0 [path/to/project.assets.json]"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo -e "${RED}Error:${RESET} ${BOLD}jq${RESET} is required but not installed."
  echo -e "  Install: ${CYAN}apt install jq${RESET}  /  ${CYAN}brew install jq${RESET}"
  exit 1
fi

# ── Parse assets.json ─────────────────────────────────────────────────────────
# Extract direct dependencies (from project.frameworks)
DIRECT_DEPS=$(jq -r '
  .project.frameworks
  | to_entries[]
  | .value.dependencies
  | keys[]
' "$ASSETS_FILE" 2>/dev/null | tr '[:upper:]' '[:lower:]' | sort -u)

# Extract all targets (one per framework)
FRAMEWORKS=$(jq -r '.targets | keys[]' "$ASSETS_FILE")

# ── Helpers ───────────────────────────────────────────────────────────────────
is_direct() {
  local name="${1,,}"  # lowercase
  echo "$DIRECT_DEPS" | grep -qx "$name"
}

# Get resolved version of a package in current framework target
get_version() {
  local fw="$1" pkg="${2,,}"
  jq -r --arg fw "$fw" --arg pkg "$pkg" '
    .targets[$fw]
    | to_entries[]
    | select((.key | split("/")[0] | ascii_downcase) == $pkg)
    | .key | split("/")[1]
  ' "$ASSETS_FILE" 2>/dev/null | head -1
}

# Get direct children of a package
get_children() {
  local fw="$1" pkg="${2,,}"
  jq -r --arg fw "$fw" --arg pkg "$pkg" '
    .targets[$fw]
    | to_entries[]
    | select((.key | split("/")[0] | ascii_downcase) == $pkg)
    | .value.dependencies
    // {}
    | to_entries[]
    | "\(.key)|\(.value)"
  ' "$ASSETS_FILE" 2>/dev/null
}

# Get all packages in a framework
get_all_packages() {
  local fw="$1"
  jq -r --arg fw "$fw" '
    .targets[$fw]
    | to_entries[]
    | .key
  ' "$ASSETS_FILE" 2>/dev/null
}

# Build reverse map: who depends on <pkg>?
get_dependents() {
  local fw="$1" pkg="${2,,}"
  jq -r --arg fw "$fw" --arg pkg "$pkg" '
    .targets[$fw]
    | to_entries[]
    | select(
        .value.dependencies
        // {}
        | keys[]
        | ascii_downcase
        | . == $pkg
      )
    | .key | split("/")[0]
  ' "$ASSETS_FILE" 2>/dev/null
}

# ── Recursive tree printer ────────────────────────────────────────────────────
# VISITED is a simple string of "pkg_lower|pkg_lower|..." to track the current
# path — avoids cycles without needing associative arrays in subshells.
# We pass it as a plain string argument so recursion works correctly in bash.

print_tree() {
  local fw="$1"
  local pkg="$2"
  local prefix="$3"       # indentation string built up as we recurse
  local is_last="$4"      # "true"/"false" — is this node last among siblings?
  local depth="${5:-0}"
  local visited="${6:-}"  # pipe-delimited list of pkg names already on this path

  local pkg_lower="${pkg,,}"

  # ── Cycle guard ──────────────────────────────────────────────────────────────
  if echo "$visited" | grep -q "|${pkg_lower}|"; then
    local branch
    [[ "$is_last" == "true" ]] && branch="└── " || branch="├── "
    echo -e "${prefix}${DIM}${branch}${pkg} ${DIM}(cycle — already in path)${RESET}"
    return
  fi
  visited="${visited}|${pkg_lower}|"

  # ── Branch drawing chars ─────────────────────────────────────────────────────
  local branch continuation
  if [[ "$depth" -eq 0 ]]; then
    branch=""
    continuation=""
  elif [[ "$is_last" == "true" ]]; then
    branch="└── "
    continuation="    "
  else
    branch="├── "
    continuation="│   "
  fi

  # ── Resolve version ──────────────────────────────────────────────────────────
  local version
  version=$(get_version "$fw" "$pkg_lower")

  # ── Colour: green = direct, purple = transitive ──────────────────────────────
  local color label
  if is_direct "$pkg_lower"; then
    color="$GREEN"; label=" ${DIM}[direct]${RESET}"
  else
    color="$PURPLE"; label=""
  fi

  # ── Print this node ──────────────────────────────────────────────────────────
  echo -e "${prefix}${DIM}${branch}${RESET}${color}${BOLD}${pkg}${RESET} ${DIM}${version}${RESET}${label}"

  # ── Collect children ─────────────────────────────────────────────────────────
  local children=()
  while IFS= read -r line; do
    [[ -n "$line" ]] && children+=("$line")
  done < <(get_children "$fw" "$pkg_lower")

  local total=${#children[@]}
  [[ $total -eq 0 ]] && return

  # ── Recurse into each child ──────────────────────────────────────────────────
  local i=0
  for child_entry in "${children[@]}"; do
    local child_name child_range
    child_name=$(echo "$child_entry" | cut -d'|' -f1)
    child_range=$(echo "$child_entry" | cut -d'|' -f2)
    i=$((i + 1))

    local child_is_last="false"
    [[ "$i" -eq "$total" ]] && child_is_last="true"

    local child_prefix="${prefix}${continuation}"

    # Append version-range hint to what the child prints as its own label
    # We do this by printing the req line just before recursing, so the
    # child's own subtree is fully expanded underneath it.
    print_tree \
      "$fw" \
      "$child_name" \
      "$child_prefix" \
      "$child_is_last" \
      $((depth + 1)) \
      "$visited"

    # Print the requested-version range as a dim annotation after the child line
    # (we can't easily inject it into the child's own echo, so we add a note line)
    # Actually: annotate inline by appending to the child's first line isn't
    # straightforward in bash recursion; instead we suffix it on the same line
    # by pre-computing and passing it down. Simplest: just add a dim sub-line.
    # This is done via the req_range printed by the child itself — so we pass it.
  done
}

# ── Mode: reverse lookup ──────────────────────────────────────────────────────
if [[ -n "$REVERSE" ]]; then
  echo -e "\n${BOLD}Who pulls in: ${YELLOW}${REVERSE}${RESET}\n"
  for fw in $FRAMEWORKS; do
    echo -e "${DIM}── ${fw} ──${RESET}"
    found=false
    while IFS= read -r parent; do
      [[ -z "$parent" ]] && continue
      found=true
      parent_version=$(get_version "$fw" "${parent,,}")
      if is_direct "${parent,,}"; then
        echo -e "  ${GREEN}${parent}${RESET} ${DIM}${parent_version} [direct]${RESET}"
      else
        echo -e "  ${PURPLE}${parent}${RESET} ${DIM}${parent_version} [transitive]${RESET}"
      fi
    done < <(get_dependents "$fw" "$REVERSE")
    $found || echo -e "  ${DIM}(nothing depends on ${REVERSE} in this framework)${RESET}"
    echo
  done
  exit 0
fi

# ── Mode: flat list ───────────────────────────────────────────────────────────
if $FLAT; then
  echo -e "\n${BOLD}Flat dependency list with ancestry${RESET}\n"
  for fw in $FRAMEWORKS; do
    echo -e "${DIM}── ${fw} ──${RESET}\n"
    while IFS= read -r pkg_full; do
      [[ -z "$pkg_full" ]] && continue
      pkg_name=$(echo "$pkg_full" | cut -d'/' -f1)
      pkg_ver=$(echo "$pkg_full"  | cut -d'/' -f2)
      pkg_lower="${pkg_name,,}"

      # Apply search filter
      if [[ -n "$SEARCH" ]] && ! echo "$pkg_lower" | grep -qi "$SEARCH"; then
        continue
      fi

      if is_direct "$pkg_lower"; then
        echo -e "  ${GREEN}${BOLD}${pkg_name}${RESET} ${DIM}${pkg_ver}${RESET}  ${DIM}[direct]${RESET}"
      else
        dependents=$(get_dependents "$fw" "$pkg_lower" | tr '\n' ',' | sed 's/,$//')
        echo -e "  ${PURPLE}${pkg_name}${RESET} ${DIM}${pkg_ver}${RESET}"
        echo -e "    ${DIM}└─ required by: ${YELLOW}${dependents}${RESET}"
      fi
    done < <(get_all_packages "$fw" | sort)
    echo
  done
  exit 0
fi

# ── Mode: tree (default) ──────────────────────────────────────────────────────
DIRECT_COUNT=0
TRANSITIVE_COUNT=0

for fw in $FRAMEWORKS; do
  while IFS= read -r pkg_full; do
    [[ -z "$pkg_full" ]] && continue
    pkg_name=$(echo "$pkg_full" | cut -d'/' -f1)
    if is_direct "${pkg_name,,}"; then
      DIRECT_COUNT=$((DIRECT_COUNT + 1))
    else
      TRANSITIVE_COUNT=$((TRANSITIVE_COUNT + 1))
    fi
  done < <(get_all_packages "$fw")
done

echo -e "\n${BOLD}NuGet Dependency Tree${RESET}"
echo -e "${DIM}Source: ${ASSETS_FILE}${RESET}"
echo -e "${GREEN}■${RESET} direct (${DIRECT_COUNT})   ${PURPLE}■${RESET} transitive (${TRANSITIVE_COUNT})\n"

for fw in $FRAMEWORKS; do
  echo -e "${BOLD}${DIM}── ${fw} ──${RESET}\n"

  # Collect direct deps for this framework
  direct_pkgs=()
  while IFS= read -r pkg_full; do
    [[ -z "$pkg_full" ]] && continue
    pkg_name=$(echo "$pkg_full" | cut -d'/' -f1)
    pkg_lower="${pkg_name,,}"

    if $DIRECT_ONLY && ! is_direct "$pkg_lower"; then continue; fi
    if [[ -n "$SEARCH" ]] && ! echo "$pkg_lower" | grep -qi "$SEARCH"; then continue; fi

    if is_direct "$pkg_lower"; then
      direct_pkgs+=("$pkg_name")
    fi
  done < <(get_all_packages "$fw" | sort)

  # If search/direct-only, also show matched transitive at root
  extra_pkgs=()
  if ! $DIRECT_ONLY && [[ -n "$SEARCH" ]]; then
    while IFS= read -r pkg_full; do
      [[ -z "$pkg_full" ]] && continue
      pkg_name=$(echo "$pkg_full" | cut -d'/' -f1)
      pkg_lower="${pkg_name,,}"
      if ! is_direct "$pkg_lower" && echo "$pkg_lower" | grep -qi "$SEARCH"; then
        extra_pkgs+=("$pkg_name")
      fi
    done < <(get_all_packages "$fw" | sort)
  fi

  all_roots=("${direct_pkgs[@]}" "${extra_pkgs[@]:-}")
  total_roots=${#all_roots[@]}

  if [[ $total_roots -eq 0 ]]; then
    echo -e "  ${DIM}(no packages match)${RESET}\n"
    continue
  fi

  for pkg_name in "${all_roots[@]}"; do
    [[ -z "$pkg_name" ]] && continue
    
    print_tree "$fw" "$pkg_name" "" "true" 0 ""
    echo
  done
done
