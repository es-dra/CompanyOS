#!/usr/bin/env sh
set -eu

SOURCE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
RAW_COMPANY_HOME=${COMPANY_OS_HOME:-"$HOME/.company-os"}
RAW_INSTALL_ROOT=${1:-"$RAW_COMPANY_HOME/CompanyOS"}
MARKER=.companyos-runtime-install

if [ -n "${PYTHON:-}" ]; then
  PYTHON_BIN=$PYTHON
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN=python3
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN=python
else
  printf '%s\n' "Python 3.11 or newer is required to canonicalize install paths" >&2
  exit 2
fi

canonical_path() {
  "$PYTHON_BIN" -c \
    'import os, sys; print(os.path.realpath(os.path.abspath(os.path.expanduser(sys.argv[1]))))' \
    "$1"
}

require_descendant() {
  parent=${1%/}
  child=$2
  case "$child" in
    "$parent"/*) ;;
    *)
      printf '%s\n' "Path escaped canonical CompanyOS home: $child" >&2
      exit 2
      ;;
  esac
}

CANONICAL_HOME=$(canonical_path "$HOME")
COMPANY_HOME=$(canonical_path "$RAW_COMPANY_HOME")
INSTALL_ROOT=$(canonical_path "$RAW_INSTALL_ROOT")

case "$COMPANY_HOME" in
  ""|"/"|"$CANONICAL_HOME")
    printf '%s\n' "Unsafe CompanyOS home: $COMPANY_HOME" >&2
    exit 2
    ;;
esac

case "$INSTALL_ROOT" in
  ""|"/"|"$CANONICAL_HOME"|"$COMPANY_HOME"|"$SOURCE_ROOT")
    printf '%s\n' "Unsafe install root: $INSTALL_ROOT" >&2
    exit 2
    ;;
esac
require_descendant "$COMPANY_HOME" "$INSTALL_ROOT"

if [ -L "$RAW_INSTALL_ROOT" ]; then
  printf '%s\n' "Refusing a symbolic-link install root: $RAW_INSTALL_ROOT" >&2
  exit 2
fi

if [ -e "$INSTALL_ROOT" ] && [ ! -f "$INSTALL_ROOT/$MARKER" ]; then
  printf '%s\n' "Refusing recursive replacement of an unmarked directory: $INSTALL_ROOT" >&2
  exit 2
fi

mkdir -p "$COMPANY_HOME/state" "$COMPANY_HOME/runs" \
  "$COMPANY_HOME/feedback-outbox" "$COMPANY_HOME/projects" "$COMPANY_HOME/demos"
for managed_dir in state runs feedback-outbox projects demos; do
  managed_path="$COMPANY_HOME/$managed_dir"
  if [ -L "$managed_path" ] || [ "$(canonical_path "$managed_path")" != "$managed_path" ]; then
    printf '%s\n' "Managed CompanyOS directory escaped through a symbolic link: $managed_path" >&2
    exit 2
  fi
  require_descendant "$COMPANY_HOME" "$managed_path"
done

STAGING="$INSTALL_ROOT.staging-$$"
CANONICAL_STAGING=$(canonical_path "$STAGING")
if [ "$CANONICAL_STAGING" != "$STAGING" ]; then
  printf '%s\n' "Staging path changed during canonicalization: $STAGING" >&2
  exit 2
fi
require_descendant "$COMPANY_HOME" "$STAGING"
if [ -L "$STAGING" ]; then
  printf '%s\n' "Refusing a symbolic-link staging path: $STAGING" >&2
  exit 2
fi

rm -rf -- "$STAGING"
mkdir -p "$STAGING"
if [ "$(canonical_path "$STAGING")" != "$STAGING" ]; then
  printf '%s\n' "Staging final path escaped CompanyOS home: $STAGING" >&2
  exit 2
fi
trap 'rm -rf -- "$STAGING"' EXIT HUP INT TERM

for item in .gitattributes AGENTS.md LICENSE README.md VERSION pyproject.toml companyos_runtime \
  bin core full-stack gfr runtime templates adapters privacy examples docs; do
  cp -R "$SOURCE_ROOT/$item" "$STAGING/"
done
printf '%s\n' "CompanyOS Runtime Kit managed installation" > "$STAGING/$MARKER"

if [ -e "$INSTALL_ROOT" ]; then
  if [ -L "$INSTALL_ROOT" ] || [ "$(canonical_path "$INSTALL_ROOT")" != "$INSTALL_ROOT" ]; then
    printf '%s\n' "Install final path changed or became a symbolic link: $INSTALL_ROOT" >&2
    exit 2
  fi
  require_descendant "$COMPANY_HOME" "$INSTALL_ROOT"
  rm -rf -- "$INSTALL_ROOT"
fi
if [ "$(canonical_path "$(dirname -- "$INSTALL_ROOT")")" != "$COMPANY_HOME" ]; then
  printf '%s\n' "Install parent changed before final move: $INSTALL_ROOT" >&2
  exit 2
fi
mv -- "$STAGING" "$INSTALL_ROOT"
trap - EXIT HUP INT TERM

ENV_FILE="$COMPANY_HOME/company-os.env"
if [ -L "$ENV_FILE" ] || [ "$(canonical_path "$ENV_FILE")" != "$ENV_FILE" ]; then
  printf '%s\n' "Environment file escaped through a symbolic link: $ENV_FILE" >&2
  exit 2
fi
require_descendant "$COMPANY_HOME" "$ENV_FILE"
cat > "$ENV_FILE" <<EOF
COMPANY_OS_HOME=$COMPANY_HOME
COMPANY_OS_REPO=$INSTALL_ROOT
COMPANY_OS_DB=$COMPANY_HOME/state/runtime.db
EOF

printf '%s\n' "Installed CompanyOS to $INSTALL_ROOT"
printf '%s\n' "Runtime home: $COMPANY_HOME"
printf '%s\n' "Initialize from the installed root: cd $INSTALL_ROOT && python -m companyos_runtime --db $COMPANY_HOME/state/runtime.db init"
