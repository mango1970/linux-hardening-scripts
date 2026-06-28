#!/bin/bash

# ==============================================================================
# Script: audit-security-essential.sh
# Descripción: Herramienta de automatización para auditoría defensiva de permisos,
#              verificación de integridad de archivos críticos y análisis de accesos.
# Autor: Mauricio Núñez G.
# Uso: sudo ./audit-security-essential.sh
# ==============================================================================

# Colores para la salida en terminal (Mejoran la legibilidad del reporte)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Control estricto de ejecución (Corta el script si hay errores inesperados)
set -euo pipefail

# Asegurar que el script se ejecute con privilegios elevados (requerido para leer logs del sistema)
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERROR] Se requieren privilegios de superusuario (sudo) para auditar el sistema.${NC}"
  exit 1
fi

echo -e "${BLUE}====================================================================${NC}"
echo -e "${BLUE}    MÓDULO DE AUDITORÍA DEFENSIVA Y GESTIÓN DE PERMISOS CRÍTICOS    ${NC}"
echo -e "${BLUE}====================================================================${NC}"

# ------------------------------------------------------------------------------
# FASE 1: Hardening e Integridad de Permisos Esenciales
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[1/3] Verificando y corrigiendo permisos de archivos del sistema...${NC}"

# Asegurar que /etc/passwd y /etc/shadow tengan los permisos restrictivos estándar (644 y 000/600)
# Esto demuestra control sobre la confidencialidad de las cuentas locales.
if [ -f /etc/passwd ]; then
  chmod 644 /etc/passwd
  chown root:root /etc/passwd
  echo -e "${GREEN}[OK] /etc/passwd configurado correctamente (644 - root:root)${NC}"
fi

if [ -f /etc/shadow ]; then
  chmod 600 /etc/shadow
  chown root:root /etc/shadow
  echo -e "${GREEN}[OK] /etc/shadow configurado correctamente (600 - root:root)${NC}"
fi

# ------------------------------------------------------------------------------
# FASE 2: Auditoría de Usuarios Activos y Privilegios
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[2/3] Analizando usuarios con UID 0 (Privilegios de Root)...${NC}"

# Buscar en /etc/passwd cualquier usuario que comparta el UID 0 (un vector común de persistencia maliciosa)
SUPERUSERS=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)

echo -e "Usuarios detectados con privilegios de superusuario:"
for user in $SUPERUSERS; do
  if [ "$user" = "root" ]; then
    echo -e "  - $user (${GREEN}Esperado${NC})"
  else
    echo -e "  - $user (${RED}ALERTA: Verificar origen de esta cuenta${NC})"
  fi
done

# Mostrar usuarios actualmente conectados en tiempo real
echo -e "\nUsuarios actualmente activos en el sistema:"
who || echo "No se pudo determinar los usuarios activos."

# ------------------------------------------------------------------------------
# FASE 3: Análisis de Accesos y Detección de Anomalías (Análisis de Logs)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[3/3] Escaneando intentos de acceso fallidos recientes...${NC}"

# Definir la ruta del log de autenticación según la distribución (Debian/Ubuntu vs RHEL/CentOS)
LOG_PATH=""
if [ -f /var/log/auth.log ]; then
  LOG_PATH="/var/log/auth.log"  # Sistemas Debian-based
elif [ -f /var/log/secure ]; then
  LOG_PATH="/var/log/secure"    # Sistemas RHEL-based
fi

if [ -n "$LOG_PATH" ] && [ -r "$LOG_PATH" ]; then
  echo -e "Últimos 5 intentos fallidos de inicio de sesión detectados:"
  # Busca patrones comunes de fallas de autenticación (fuerza bruta)
  grep -i "failed" "$LOG_PATH" | tail -n 5 || echo "No se encontraron intentos fallidos recientes."
else
  echo -e "${YELLOW}[INFO] Archivo de registros de autenticación inaccesible o vacío en este entorno.${NC}"
fi

echo -e "\n${GREEN}====================================================================${NC}"
echo -e "${GREEN}             AUDITORÍA COMPLETADA DE FORMA EXITOSA                  ${NC}"
echo -e "${GREEN}====================================================================${NC}"