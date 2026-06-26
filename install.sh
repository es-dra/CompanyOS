#!/usr/bin/env sh
set -eu

SOURCE_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
COMPANY_HOME="${COMPANY_OS_HOME:-$HOME/.company-os}"
INSTALL_ROOT="${1:-$COMPANY_HOME/CompanyOS}"

mkdir -p "$COMPANY_HOME/runs" "$COMPANY_HOME/feedback-outbox" "$COMPANY_HOME/projects"
rm -rf "$INSTALL_ROOT"
mkdir -p "$INSTALL_ROOT"

for item in AGENTS.md LICENSE README.md VERSION bin core full-stack gfr runtime templates adapters privacy examples; do
  cp -R "$SOURCE_ROOT/$item" "$INSTALL_ROOT/"
done

cat > "$COMPANY_HOME/company-os.env" <<EOF
COMPANY_OS_HOME=$COMPANY_HOME
COMPANY_OS_REPO=$INSTALL_ROOT
EOF

printf '%s\n' "Installed CompanyOS to $INSTALL_ROOT"
printf '%s\n' "Runtime home: $COMPANY_HOME"
