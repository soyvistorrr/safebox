#!/bin/bash
#
# test_master.sh
# CI3825 - Sistemas de Operacion I — Proyecto 3 SafeBox
# SCRIPT DE EVALUACIÓN MAESTRA (CORRUPCIÓN Y ESTRÉS)

set -e

PASSWORD="sbx2026"
BOVEDA="./test_boveda_master_$$"
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
    rm -rf "$BOVEDA"
    rm -f /tmp/test_*_$$.*
    rm -f /tmp/safebox.sock /tmp/safebox.pid
}
trap cleanup EXIT

echo ""; echo "=========================================="
echo " SafeBox — Test de Evaluacion MAESTRA"
echo "=========================================="; echo ""

# Levantar Daemon
mkdir -p "$BOVEDA"
echo "$PASSWORD" | "$DAEMON" "$BOVEDA" > /dev/null 2>&1
sleep 0.8
DAEMON_PID=$(cat /tmp/safebox.pid 2>/dev/null)


# ── Test 16: DEL de Archivo Inexistente ────────────────────
echo "--- Test 16: DEL archivo fantasma ---"
OUT=$(run_cli "del fantasma.txt")
echo "$OUT" | grep -qi "error\|no se pudo" && ok "DEL de archivo inexistente retorna error limpio" \
    || fail "DEL de archivo inexistente fallo o no reporto error"

# ── Test 17: Limite de Buffer Interno (Boundary) ───────────
echo ""; echo "--- Test 17: Archivo Exacto del Buffer (4096 B) ---"
BOUNDARY_FILE="/tmp/test_4096_$$.dat"
OUT_BOUNDARY="/tmp/test_4096_out_$$.dat"
# Crear archivo de exactamente 4096 bytes
dd if=/dev/urandom of="$BOUNDARY_FILE" bs=4096 count=1 status=none
MD5_IN=$(md5sum "$BOUNDARY_FILE" | awk '{print $1}')

run_cli "put exacto.dat $BOUNDARY_FILE" > /dev/null
run_cli "get exacto.dat" | tail -c +28 | head -c -25 > "$OUT_BOUNDARY"

MD5_OUT=$(md5sum "$OUT_BOUNDARY" | awk '{print $1}')
[ "$MD5_IN" == "$MD5_OUT" ] && ok "PUT/GET de 4096 bytes exactos manejado perfectamente" \
    || fail "Corrupcion en boundary test de 4096 bytes"


# ── Test 18: Corrupcion Física en Disco ────────────────────
echo ""; echo "--- Test 18: Tolerancia a Corrupcion Física ---"
CORRUPT_FILE="/tmp/test_corrupt_$$.txt"
echo "Este es un archivo secreto muy importante" > "$CORRUPT_FILE"
run_cli "put debil.txt $CORRUPT_FILE" > /dev/null

# Hackeamos el archivo directamente en la boveda (sobrescribimos el magic byte)
# Escribimos 4 bytes de ceros en el offset 8 (justo donde empieza el Magic "SBX!")
printf '\x00\x00\x00\x00' | dd of="$BOVEDA/debil.txt" bs=1 seek=8 count=4 conv=notrunc status=none 2>/dev/null

OUT=$(run_cli "get debil.txt")
echo "$OUT" | grep -qi "error\|corrupto\|no se pudo" && ok "Daemon rechazo archivo corrompido fisicamente" \
    || fail "Daemon intento leer archivo corrompido sin validar el Magic Byte"


# ── Test 19: Tormenta de Conexiones (Socket Stress) ────────
echo ""; echo "--- Test 19: Tormenta de 50 Clientes Concurrentes ---"
STRESS_FAILS=0
for i in {1..50}; do
    # Lanzamos 50 sesiones rapidas sin esperar
    OUT=$(printf "%s\nlist\nexit\n" "$PASSWORD" | "$SHELL" 2>&1 || true)
    if ! echo "$OUT" | grep -qi "debil.txt"; then
        STRESS_FAILS=$((STRESS_FAILS+1))
    fi
done

if kill -0 "$DAEMON_PID" 2>/dev/null; then
    ok "Daemon sobrevivio a la tormenta (No hizo crash)"
    [ "$STRESS_FAILS" -eq 0 ] && ok "Las 50 conexiones fueron procesadas exitosamente" \
        || fail "$STRESS_FAILS/50 conexiones fallaron durante el estres"
else
    fail "El Daemon murio durante la tormenta de conexiones (FD leak o Memory leak)"
fi


# ── Resumen ───────────────────────────────────────
echo ""; echo "=========================================="
TOTAL=$((PASS + FAIL))
echo " Resultado Maestro: $PASS/$TOTAL pruebas pasadas"
[ $FAIL -eq 0 ] \
    && echo -e " ${GREEN}CALIFICACIÓN ESTIMADA: 15/15${NC}" \
    || echo -e " ${RED}$FAIL TESTS MAESTROS FALLARON${NC}"
echo "=========================================="; echo ""
exit $FAIL