#!/usr/bin/env bash
# ==============================================================================
# Pre-Commit Hook: Secret & Credential Leak Prevention
# ==============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
START_TS=$(date +%s)

log_info()  { echo -e "${DIM}[${TIMESTAMP}]${NC} ${CYAN}[INFO]${NC}  $1"; }
log_ok()    { echo -e "${DIM}[${TIMESTAMP}]${NC} ${GREEN}[PASS]${NC}  $1"; }
log_warn()  { echo -e "${DIM}[${TIMESTAMP}]${NC} ${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${DIM}[${TIMESTAMP}]${NC} ${RED}[ALERT]${NC} $1"; }

STAGED_COUNT=$(git diff --cached --name-only | wc -l | tr -d ' ')
log_info "Iniciando auditoria de segurança em ${STAGED_COUNT} arquivo(s) staged..."

# 1. Bloqueia commits diretos de arquivos sensíveis
BLOCKED_FILES=$(git diff --cached --name-only | grep -E "(^|/)\.env($|\..*)|\.pem$|\.key$|\.secret$" | grep -v "\.env\.example$" || true)

if [ -n "$BLOCKED_FILES" ]; then
    log_error "Arquivo sensível detectado no índice de commit:"
    echo "$BLOCKED_FILES" | sed 's/^/  -> /'
    log_warn "Remova do git com 'git reset HEAD <arquivo>' e adicione ao .gitignore."
    exit 1
fi

# 2. Padrões de segredos e credenciais para inspecionar no diff staged
PATTERNS=(
    "(password|passwd|pwd|secret)[[:space:]]*[:=][[:space:]]*['\"][^'\"]{4,}['\"]"
    "(api[_-]?key|auth[_-]?token|access[_-]?token)[[:space:]]*[:=][[:space:]]*['\"][a-zA-Z0-9_\-]{16,}['\"]"
    "BEGIN[[:space:]]+(RSA|EC|DSA|OPENSSH)?[[:space:]]*PRIVATE[[:space:]]+KEY"
    "postgres(ql)?:\/\/[a-zA-Z0-9_\-\.]+:[^@\s\$]+@"
    "sk-[a-zA-Z0-9]{20,}"
    "sk-ant-[a-zA-Z0-9_\-]{20,}"
    "AIzaSy[a-zA-Z0-9_\-]{33}"
    "gh[pousr]_[a-zA-Z0-9]{36}"
    "163\.176\.115\.188"
)

FOUND_SECRET=0
RULES_CHECKED=${#PATTERNS[@]}

for pattern in "${PATTERNS[@]}"; do
    MATCHES=$(git diff --cached -U0 | grep -E "^[+]" | grep -v -E "^[+]{3}" | grep -i -E -e "$pattern" || true)
    if [ -n "$MATCHES" ]; then
        log_error "Possível credencial ou segredo detectado no diff (regra: ${pattern:0:24}...):"
        echo "$MATCHES" | head -n 5 | sed 's/^/  /'
        FOUND_SECRET=1
    fi
done

if [ $FOUND_SECRET -eq 1 ]; then
    log_error "Commit bloqueado pela política de segurança DevSecOps."
    log_warn "Utilize variáveis de ambiente ou placeholders seguros (ex: \${DB_PASSWORD})."
    exit 1
fi

END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))
log_ok "Auditoria concluída (${RULES_CHECKED} regras verificadas em ${ELAPSED}s). Nenhum segredo exposto."
exit 0
