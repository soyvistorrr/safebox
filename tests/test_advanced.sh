#!/bin/bash
#
# test_advanced.sh
# CI3825 - Sistemas de Operacion I — Proyecto 3 SafeBox
# SCRIPT DE EVALUACIÓN AVANZADA (CORREGIDO)

set -e

PASSWORD="sbx2026"
BOVEDA="./test_boveda_adv_$$"
DAEMON="./safebox-daemon"
SHELL="./safebox-shell"
LOG="/tmp/safebox.log"
DAEMON_PID=""
PASS=0
FAIL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}[OK]${NC}   $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }

run_cli() { printf "%s\n%s\nexit\n" "$PASSWORD" "$1" | "$SHELL" 2>&1 || true; }

cleanup() {
    [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null && \
        kill -TERM "$DAEMON_PID" 2>/dev/null && sleep 0.4
    rm -rf "$BOVEDA" "./boveda_readonly_$$"
    rm -f /tmp/test_*_$$.*
    rm -f /tmp/safebox.sock /tmp/safebox.pid
}
trap cleanup EXIT

echo ""; echo "=========================================="
echo " SafeBox — Test de Evaluacion AVANZADA"
echo "=========================================="; echo ""

# ── Test 11: Directorio sin permisos ───────────────────────
echo "--- Test 11: Directorio de solo lectura ---"
RO_DIR="./boveda_readonly_$$"
mkdir -p "$RO_DIR"
chmod 400 "$RO_DIR" 

OUT=$(echo "$PASSWORD" | "$DAEMON" "$RO_DIR" 2>&1 || true)
echo "$OUT" | grep -qi "permisos\|error" && ok "Daemon aborta si no hay permisos W_OK" \
    || fail "Daemon arranco en directorio sin permisos de escritura"

chmod 700 "$RO_DIR" 

mkdir -p "$BOVEDA"
echo "$PASSWORD" | "$DAEMON" "$BOVEDA" > /dev/null 2>&1
sleep 0.8
DAEMON_PID=$(cat /tmp/safebox.pid 2>/dev/null)

# ── Test 12: Archivo Vacío (0 bytes) ───────────────────────
echo ""; echo "--- Test 12: Archivo de 0 bytes ---"
EMPTY_FILE="/tmp/test_empty_$$.txt"
touch "$EMPTY_FILE"
run_cli "put vacio.txt $EMPTY_FILE" > /dev/null

SIZE=$(stat -c%s "$BOVEDA/vacio.txt" 2>/dev/null || echo "0")
[ "$SIZE" -eq 12 ] && ok "PUT archivo vacio guardo 12 bytes exactos (Header + Magic)" \
    || fail "PUT archivo vacio ocupo $SIZE bytes (se esperaban 12)"

OUT=$(run_cli "get vacio.txt")
[ -z "$(echo "$OUT" | grep -v 'safebox' | grep -v 'sesion')" ] && ok "GET archivo vacio manejado correctamente" \
    || fail "GET archivo vacio devolvio basura o fallo"

# ── Test 13: Archivo Binario (Transparencia 8-bits) ────────
echo ""; echo "--- Test 13: Archivo Binario (Random Data) ---"
BIN_FILE="/tmp/test_bin_$$.dat"
OUT_BIN="/tmp/test_bin_out_$$.dat"
head -c 5000 /dev/urandom > "$BIN_FILE"
MD5_IN=$(md5sum "$BIN_FILE" | awk '{print $1}')

run_cli "put binario.dat $BIN_FILE" > /dev/null
# Extraer binario de la consola omitiendo prompts (9 bytes al inicio, 25 al final)
run_cli "get binario.dat" | tail -c +28 | head -c -25 > "$OUT_BIN"

MD5_OUT=$(md5sum "$OUT_BIN" | awk '{print $1}')
[ "$MD5_IN" == "$MD5_OUT" ] && ok "PUT/GET de archivo BINARIO exitoso (md5 coincide)" \
    || fail "Corrupcion en archivo binario (md5 difiere)"

# ── Test 14: Sobreescritura (Truncate) ─────────────────────
echo ""; echo "--- Test 14: Sobreescritura de archivo ---"
FILE_A="/tmp/test_A_$$.txt"
FILE_B="/tmp/test_B_$$.txt"
echo "AAAAA" > "$FILE_A"
echo "B" > "$FILE_B"

run_cli "put sobreescribir.txt $FILE_A" > /dev/null
run_cli "put sobreescribir.txt $FILE_B" > /dev/null

OUT=$(run_cli "get sobreescribir.txt")
echo "$OUT" | grep -q "B" && ! echo "$OUT" | grep -q "A" && ok "Archivo sobreescrito y truncado correctamente" \
    || fail "Sobreescritura fallo (posible basura del archivo anterior)"

# ── Test 15: Archivo Grande (Stress Test 1 MB) ─────────────
echo ""; echo "--- Test 15: Archivo Grande (1 MB) ---"
BIG_FILE="/tmp/test_big_$$.dat"
BIG_OUT="/tmp/test_big_out_$$.dat"
dd if=/dev/urandom of="$BIG_FILE" bs=1M count=1 status=none
MD5_BIG_IN=$(md5sum "$BIG_FILE" | awk '{print $1}')

run_cli "put grande.dat $BIG_FILE" > /dev/null
run_cli "get grande.dat" | tail -c +28 | head -c -25 > "$BIG_OUT"

MD5_BIG_OUT=$(md5sum "$BIG_OUT" | awk '{print $1}')
[ "$MD5_BIG_IN" == "$MD5_BIG_OUT" ] && ok "PUT/GET de archivo de 1MB exitoso" \
    || fail "Fallo al transferir archivo grande"

# ── Resumen ───────────────────────────────────────
echo ""; echo "=========================================="
TOTAL=$((PASS + FAIL))
echo " Resultado Avanzado: $PASS/$TOTAL pruebas pasadas"
[ $FAIL -eq 0 ] \
    && echo -e " ${GREEN}CÓDIGO A PRUEBA DE BALAS${NC}" \
    || echo -e " ${RED}$FAIL TESTS AVANZADOS FALLARON${NC}"
echo "=========================================="; echo ""
exit $FAIL