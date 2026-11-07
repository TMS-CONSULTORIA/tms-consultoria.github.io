#!/usr/bin/env bash
# ==============================================================================
# Pre-Commit Hook: Secret & Credential Leak Prevention
# ==============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🔍 [Security Hook] Verificando arquivos staged em busca de credenciais e segredos..."

# 1. Bloqueia commits diretos de arquivos sensíveis
BLOCKED_FILES=$(git diff --cached --name-only | grep -E "(^|/)\.env($|\..*)|\.pem$|\.key$|\.secret$" | grep -v "\.env\.example$" || true)

if [ -n "$BLOCKED_FILES" ]; then
    echo -e "${RED}❌ ERRO: Arquivo sensível detectado no commit:${NC}"
    echo "$BLOCKED_FILES"
    echo -e "${YELLOW}Remova do git com 'git reset HEAD <arquivo>' e adicione ao .gitignore!${NC}"
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

for pattern in "${PATTERNS[@]}"; do
    MATCHES=$(git diff --cached -U0 | grep -E "^[+]" | grep -v -E "^[+]{3}" | grep -i -E -e "$pattern" || true)
    if [ -n "$MATCHES" ]; then
        echo -e "${RED}❌ ERRO: Possível credencial / segredo detectado no diff:${NC}"
        echo "$MATCHES" | head -n 5
        FOUND_SECRET=1
    fi
done

if [ $FOUND_SECRET -eq 1 ]; then
    echo -e "${RED}🚨 Commit bloqueado por segurança! Remova as credenciais antes de commitar.${NC}"
    echo -e "${YELLOW}Dica: Utilize variáveis de ambiente ou placeholders (ex: \${DB_PASSWORD}).${NC}"
    exit 1
fi

echo -e "${GREEN}✅ [Security Hook] Nenhum segredo ou credencial detectado. Commit liberado!${NC}"
exit 0
