#!/bin/bash

# ==============================================================================
# Script: audit-security-essential.sh
# Descripción: Herramienta de automatización para auditoría defensiva de 5 fases:
#   1. Hardening de permisos críticos con verificación previa
#   2. Auditoría avanzada de usuarios y privilegios
#   3. Análisis de logs con agregación por IP y detección de persistencia
#   4. Detección de SUID/SGID anómalos, puertos y conexiones
#   5. Generación de reporte TXT + JSON para integración SIEM
# Autor: Mauricio Núñez G.
# Versión: 2.0
# Uso: sudo ./linux-hardening-scripts.sh [--json] [--quiet]
# Salida: reporte en consola + /var/log/hardening-audit-YYYYMMDD-HHMMSS.json
# ==============================================================================

# ------------------------------------------------------------------------------
# CONFIGURACIÓN INICIAL
# ------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

set -euo pipefail
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
TIMESTAMP_FILE=$(date '+%Y%m%d-%H%M%S')
REPORT_DIR="/var/log/hardening-audit"
REPORT_TXT="${REPORT_DIR}/audit-${TIMESTAMP_FILE}.txt"
REPORT_JSON="${REPORT_DIR}/audit-${TIMESTAMP_FILE}.json"
LOG_FILE="${REPORT_DIR}/hardening.log"
QUIET_MODE=false
ALERTS=0
WARNINGS=0
JSON_FINDINGS="[]"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERROR] Se requieren privilegios de superusuario (sudo).${NC}"
  exit 1
fi

for arg in "$@"; do
  case $arg in
    --quiet) QUIET_MODE=true ;;
  esac
done

mkdir -p "$REPORT_DIR"

log() { echo -e "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE" > /dev/null; }
info() { $QUIET_MODE || echo -e "$@"; }
ok()   { info "${GREEN}[OK]${NC} $@"; log "[OK] $@"; }
warn() { info "${YELLOW}[WARN]${NC} $@"; log "[WARN] $@"; ((WARNINGS++)) || true; }
alert(){ info "${RED}[ALERT]${NC} $@"; log "[ALERT] $@"; ((ALERTS++)) || true; }

add_finding() {
  local severity="$1" category="$2" detail="$3" evidence="$4"
  JSON_FINDINGS=$(echo "$JSON_FINDINGS" | jq -c \
    --arg s "$severity" --arg c "$category" --arg d "$detail" --arg e "$evidence" \
    '. + [{"severity":$s,"category":$c,"detail":$d,"evidence":$e,"timestamp":"'"$TIMESTAMP"'"}]' 2>/dev/null) || true
}

# ==============================================================================
# FASE 1: HARDENING DE PERMISOS CRÍTICOS (con verificación previa)
# ==============================================================================
run_phase1() {
  info "\n${BLUE}====================================================================${NC}"
  info "${BLUE}    FASE 1/5: HARDENING E INTEGRIDAD DE PERMISOS CRÍTICOS          ${NC}"
  info "${BLUE}====================================================================${NC}"

  declare -A PERM_MAP
  PERM_MAP["/etc/passwd"]="644"
  PERM_MAP["/etc/shadow"]="600"
  PERM_MAP["/etc/group"]="644"
  PERM_MAP["/etc/gshadow"]="600"
  PERM_MAP["/etc/sudoers"]="440"
  PERM_MAP["/etc/ssh/sshd_config"]="600"

  for file in "${!PERM_MAP[@]}"; do
    if [ ! -f "$file" ]; then
      warn "Archivo $file no existe en este sistema — omitiendo."
      continue
    fi

    local current_perm
    current_perm=$(stat -c '%a' "$file" 2>/dev/null || echo "unknown")
    local current_owner
    current_owner=$(stat -c '%U:%G' "$file" 2>/dev/null || echo "unknown:unknown")
    local target_perm="${PERM_MAP[$file]}"

    if [ "$current_perm" != "$target_perm" ]; then
      chmod "$target_perm" "$file" 2>/dev/null && \
        info "  ${CYAN}[FIXED]${NC} $file: permisos $current_perm -> $target_perm" || \
        warn "No se pudo corregir $file (actual: $current_perm, esperado: $target_perm)"
      add_finding "medium" "file_permissions" "Permisos corregidos en $file" "Antes:$current_perm -> Ahora:$target_perm"
      log "[FASE1] Corregido $file: $current_perm -> $target_perm"
    else
      ok "$file (${target_perm})"
    fi

    if [ "$current_owner" != "root:root" ]; then
      chown root:root "$file" 2>/dev/null && \
        info "  ${CYAN}[FIXED]${NC} $file: propietario $current_owner -> root:root" || \
        warn "No se pudo corregir propietario de $file (actual: $current_owner)"
      add_finding "medium" "file_ownership" "Propietario corregido en $file" "Antes:$current_owner -> root:root"
    fi
  done

  info "\n${YELLOW}[FASE 1] Resumen de archivos con permisos indebidos detectados y corregidos.${NC}"
}

# ==============================================================================
# FASE 2: AUDITORÍA AVANZADA DE USUARIOS Y PRIVILEGIOS
# ==============================================================================
run_phase2() {
  info "\n${BLUE}====================================================================${NC}"
  info "${BLUE}    FASE 2/5: AUDITORÍA AVANZADA DE USUARIOS Y PRIVILEGIOS         ${NC}"
  info "${BLUE}====================================================================${NC}"

  # --- 2.1 Usuarios con UID 0 (vector de persistencia maliciosa) ---
  info "\n${YELLOW}[2.1] Usuarios con UID 0 (privilegios de root):${NC}"
  while IFS=: read -r user _ uid _; do
    if [ "$uid" -eq 0 ]; then
      if [ "$user" = "root" ]; then
        ok "root (esperado)"
      else
        alert "USUARIO NO AUTORIZADO CON UID 0: $user — posible backdoor"
        add_finding "critical" "uid_zero" "Usuario no-root con UID 0 detectado" "$user"
      fi
    fi
  done < /etc/passwd

  # --- 2.2 Miembros de grupos sudo/wheel ---
  info "\n${YELLOW}[2.2] Usuarios con privilegios sudo:${NC}"
  for group in sudo wheel; do
    if getent group "$group" &>/dev/null; then
      local members
      members=$(getent group "$group" | cut -d: -f4)
      if [ -n "$members" ]; then
        info "  Grupo $group: $members"
      else
        info "  Grupo $group: sin miembros (correcto si no se esperan)"
      fi
    fi
  done

  # También analizar /etc/sudoers.d/
  info "  Entradas en sudoers adicionales:"
  if [ -d /etc/sudoers.d ]; then
    for f in /etc/sudoers.d/*; do
      [ -f "$f" ] && info "    -> $f"
    done
  fi

  # --- 2.3 Usuarios sin contraseña (cuentas bloqueadas vs vacías) ---
  info "\n${YELLOW}[2.3] Cuentas sin contraseña o con contraseña vacía:${NC}"
  while IFS=: read -r user passwd _ uid _; do
    if [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -le 60000 ] 2>/dev/null; then
      if [ -z "$passwd" ] || [ "$passwd" = "" ]; then
        alert "Usuario $user (UID:$uid) no tiene contraseña definida"
        add_finding "high" "no_password" "Usuario sin contraseña" "$user (UID:$uid)"
      fi
    fi
  done < /etc/shadow 2>/dev/null || warn "No se pudo leer /etc/shadow"

  # --- 2.4 Cuentas de sistema con shell interactiva ---
  info "\n${YELLOW}[2.4] Cuentas de sistema (UID < 1000) con shell interactiva:${NC}"
  local system_shells_found=0
  while IFS=: read -r user _ uid _ _ shell; do
    if [ "$uid" -lt 1000 ] 2>/dev/null && [ "$uid" -ge 0 ] 2>/dev/null; then
      case "$shell" in
        */bash|*/sh|*/zsh|*/dash)
          warn "Cuenta de sistema '$user' (UID:$uid) tiene shell interactiva: $shell"
          add_finding "medium" "system_shell" "Cuenta de sistema con shell interactiva" "$user (UID:$uid, shell:$shell)"
          ((system_shells_found++)) || true
          ;;
      esac
    fi
  done < /etc/passwd
  [ "$system_shells_found" -eq 0 ] && ok "Ninguna cuenta de sistema con shell interactiva detectada"

  # --- 2.5 Usuarios conectados y sesiones activas ---
  info "\n${YELLOW}[2.5] Usuarios activos en el sistema:${NC}"
  if command -v w &>/dev/null; then
    w -h 2>/dev/null || info "  (sin sesiones activas detectables)"
  elif command -v who &>/dev/null; then
    who 2>/dev/null || info "  (sin sesiones detectables)"
  else
    warn "Comandos w/who no disponibles"
  fi

  # --- 2.6 Procesos ejecutándose como root ---
  info "\n${YELLOW}[2.6] Procesos ejecutados por root (top 10 por CPU):${NC}"
  ps -eo user,pid,%cpu,%mem,comm --sort=-%cpu --no-headers 2>/dev/null | \
    grep '^root' | head -10 || info "  No se pudo obtener lista de procesos"

  info "\n${YELLOW}[FASE 2] Auditoría de usuarios completada.${NC}"
}

# ==============================================================================
# FASE 3: ANÁLISIS DE LOGS, CRON Y SERVICIOS OCULTOS
# ==============================================================================
run_phase3() {
  info "\n${BLUE}====================================================================${NC}"
  info "${BLUE}    FASE 3/5: ANÁLISIS DE LOGS, CRON Y SERVICIOS OCULTOS           ${NC}"
  info "${BLUE}====================================================================${NC}"

  # --- 3.1 Detección del archivo de log de autenticación ---
  local log_path=""
  if [ -f /var/log/auth.log ] && [ -r /var/log/auth.log ]; then
    log_path="/var/log/auth.log"
  elif [ -f /var/log/secure ] && [ -r /var/log/secure ]; then
    log_path="/var/log/secure"
  fi

  # --- 3.2 Búsqueda de intentos fallidos con agregación por IP (detección de fuerza bruta) ---
  if [ -n "$log_path" ]; then
    info "\n${YELLOW}[3.1] Top 10 IPs con intentos fallidos (posible fuerza bruta):${NC}"
    local brute_data
    brute_data=$(grep -iE "(failed|invalid|break-in|authentication failure|bad password|incorrect password)" "$log_path" 2>/dev/null | \
      grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -10)
    if [ -n "$brute_data" ]; then
      echo "$brute_data" | while read -r count ip; do
        if [ "$count" -gt 5 ] 2>/dev/null; then
          alert "Posible fuerza bruta: $count intentos fallidos desde IP $ip"
          add_finding "high" "brute_force" "Posible ataque de fuerza bruta detectado" "IP:$ip intentos:$count"
        else
          info "  IP $ip: $count intentos fallidos"
        fi
      done
    else
      ok "No se detectaron intentos fallidos recientes en $log_path"
    fi

    # --- 3.3 Últimos accesos exitosos ---
    info "\n${YELLOW}[3.2] Últimos 5 accesos exitosos:${NC}"
    grep -i "session opened" "$log_path" 2>/dev/null | tail -5 || info "  Sin datos de sesiones abiertas"
  else
    warn "Archivo de logs de autenticación no accesible"
    # Intentar fallback con journalctl
    if command -v journalctl &>/dev/null; then
      info "${YELLOW}[3.1-fallback] Intentando via journalctl:${NC}"
      journalctl -u sshd --since "1 hour ago" --no-pager 2>/dev/null | \
        grep -iE "(failed|invalid)" | tail -10 || info "  Sin datos en journalctl"
    fi
  fi

  # --- 3.4 Detección de tareas cron sospechosas ---
  info "\n${YELLOW}[3.3] Análisis de tareas cron (todos los usuarios):${NC}"
  for cron_dir in /var/spool/cron/crontabs /var/spool/cron; do
    if [ -d "$cron_dir" ]; then
      for user_cron in "$cron_dir"/*; do
        if [ -f "$user_cron" ]; then
          local cron_user
          cron_user=$(basename "$user_cron")
          local cron_content
          cron_content=$(grep -v '^#' "$user_cron" 2>/dev/null | grep -v '^$' || true)
          if [ -n "$cron_content" ]; then
            warn "Tareas cron para usuario '$cron_user' detectadas"
            echo "$cron_content" | while IFS= read -r line; do
              info "    -> $line"
            done
            add_finding "info" "cron_task" "Tarea cron de usuario" "$cron_user: $(echo "$cron_content" | tr '\n' ' ')"
          fi
        fi
      done
    fi
  done

  # System-wide crontab
  if [ -f /etc/crontab ] && [ -r /etc/crontab ]; then
    local sys_cron
    sys_cron=$(grep -v '^#' /etc/crontab 2>/dev/null | grep -v '^$' || true)
    [ -n "$sys_cron" ] && info "  /etc/crontab contiene entradas activas" && \
      echo "$sys_cron" | while IFS= read -r line; do info "    -> $line"; done
  fi

  # cron.d/, cron.daily/, cron.hourly/, cron.weekly/, cron.monthly/
  for cron_glob in /etc/cron.d/* /etc/cron.{daily,hourly,weekly,monthly}/*; do
    if [ -f "$cron_glob" ]; then
      info "  Script programado: $cron_glob"
    fi
  done

  # --- 3.5 Detección de servicios systemd ocultos o no nativos ---
  info "\n${YELLOW}[3.4] Servicios systemd habilitados (posibles persistentes):${NC}"
  if command -v systemctl &>/dev/null; then
    systemctl list-unit-files --type=service --state=enabled 2>/dev/null | \
      grep -v '^UNIT' | grep -v '^$' | head -20 | while IFS= read -r line; do
      info "  $line"
    done
  else
    info "  systemctl no disponible (sistema sin systemd)"
  fi

  info "\n${YELLOW}[FASE 3] Análisis de logs y persistencia completado.${NC}"
}

# ==============================================================================
# FASE 4: SUID/SGID ANÓMALOS, PUERTOS Y CONEXIONES
# ==============================================================================
run_phase4() {
  info "\n${BLUE}====================================================================${NC}"
  info "${BLUE}    FASE 4/5: SUID/SGID ANÓMALOS, PUERTOS Y CONEXIONES             ${NC}"
  info "${BLUE}====================================================================${NC}"

  # --- 4.1 Archivos SUID en binarios del sistema ---
  info "\n${YELLOW}[4.1] Archivos con bit SUID en /usr/bin y /usr/sbin:${NC}"
  local suid_found
  suid_found=$(find /usr/bin /usr/sbin /bin /sbin -type f -perm -4000 2>/dev/null)
  local suid_count
  suid_count=$(echo "$suid_found" | grep -c '^/' || echo 0)

  if [ -n "$suid_found" ]; then
    # Baseline de SUID legítimos comunes
    local legitimate_suid="passwd|sudo|su|ping|mount|umount|newgrp|chsh|chfn|gpasswd|pkexec|fusermount|unix_chkpwd|bwrap|ssh-keysign|polkit-agent-helper"
    local anomalous=0
    echo "$suid_found" | while IFS= read -r file; do
      local basename_file
      basename_file=$(basename "$file")
      if echo "$basename_file" | grep -qE "^($legitimate_suid)$"; then
        info "  ${GREEN}[LEGIT]${NC} $file"
      else
        alert "SUID ANÓMALO: $file"
        add_finding "critical" "suid_anomaly" "Archivo SUID fuera del baseline conocido" "$file"
        ((anomalous++)) || true
      fi
    done
  else
    ok "No se encontraron archivos SUID en rutas del sistema"
  fi

  # --- 4.2 Archivos SGID ---
  info "\n${YELLOW}[4.2] Archivos con bit SGID en rutas del sistema:${NC}"
  local sgid_found
  sgid_found=$(find /usr/bin /usr/sbin /bin /sbin -type f -perm -2000 2>/dev/null)
  if [ -n "$sgid_found" ]; then
    echo "$sgid_found" | while IFS= read -r file; do
      info "  $file"
    done
  else
    ok "No se encontraron archivos SGID en rutas del sistema"
  fi

  # --- 4.3 Puertos en escucha (listening) ---
  info "\n${YELLOW}[4.3] Puertos TCP/UDP en escucha:${NC}"
  if command -v ss &>/dev/null; then
    ss -tulnp 2>/dev/null | grep -v '^Netid' | while IFS= read -r line; do
      # Extraer IP:puerto y proceso
      local port_info
      port_info=$(echo "$line" | awk '{print $5, $7}')
      info "  $port_info"
    done
  elif command -v netstat &>/dev/null; then
    netstat -tulnp 2>/dev/null | grep 'LISTEN' | while IFS= read -r line; do
      info "  $line"
    done
  else
    warn "Ni ss ni netstat disponibles para escanear puertos"
  fi

  # --- 4.4 Conexiones establecidas (potenciales C2 o shells reversas) ---
  info "\n${YELLOW}[4.4] Conexiones establecidas (potenciales shells reversas/C2):${NC}"
  if command -v ss &>/dev/null; then
    ss -tnp state established 2>/dev/null | grep -v '^Netid' | while IFS= read -r line; do
      info "  $line"
    done
  elif command -v netstat &>/dev/null; then
    netstat -tnp 2>/dev/null | grep 'ESTABLISHED' | while IFS= read -r line; do
      info "  $line"
    done
  else
    warn "No se pueden listar conexiones establecidas"
  fi

  # --- 4.5 Directorios world-writable (posible escalación) ---
  info "\n${YELLOW}[4.5] Directorios con permisos world-writable en /etc y /var:${NC}"
  local world_write
  world_write=$(find /etc /var -type d -perm -o+w ! -path "*/proc/*" ! -path "*/sys/*" 2>/dev/null | head -15)
  if [ -n "$world_write" ]; then
    echo "$world_write" | while IFS= read -r dir; do
      warn "Directorio world-writable: $dir"
      add_finding "medium" "world_writable" "Directorio con permisos de escritura global" "$dir"
    done
  else
    ok "No se detectaron directorios world-writable en /etc y /var"
  fi

  info "\n${YELLOW}[FASE 4] Análisis de SUID, puertos y conexiones completado.${NC}"
}

# ==============================================================================
# FASE 5: GENERACIÓN DE REPORTE TXT + JSON (INTEGRABLE CON SIEM)
# ==============================================================================
run_phase5() {
  info "\n${BLUE}====================================================================${NC}"
  info "${BLUE}    FASE 5/5: GENERACIÓN DE REPORTES TXT Y JSON (SIEM-READY)       ${NC}"
  info "${BLUE}====================================================================${NC}"

  local hostname_info
  hostname_info=$(hostname 2>/dev/null || echo "unknown")
  local kernel_info
  kernel_info=$(uname -r 2>/dev/null || echo "unknown")
  local os_info
  os_info=$(cat /etc/os-release 2>/dev/null | grep '^PRETTY_NAME' | cut -d= -f2 | tr -d '"' || echo "unknown")
  local uptime_info
  uptime_info=$(uptime -p 2>/dev/null || echo "unknown")
  local total_findings=$((ALERTS + WARNINGS))

  # --- 5.1 Reporte TXT ---
  {
    echo "========================================================================"
    echo "  REPORTE DE AUDITORÍA DEFENSIVA DE SEGURIDAD"
    echo "========================================================================"
    echo "  Fecha de ejecución : $TIMESTAMP"
    echo "  Hostname           : $hostname_info"
    echo "  Kernel             : $kernel_info"
    echo "  Sistema Operativo  : $os_info"
    echo "  Uptime             : $uptime_info"
    echo "------------------------------------------------------------------------"
    echo "  Alertas críticas   : $ALERTS"
    echo "  Advertencias       : $WARNINGS"
    echo "  Total hallazgos    : $total_findings"
    echo "========================================================================"
    echo ""
    echo "[NOTA] Este reporte está diseñado para ser consumido por herramientas SIEM"
    echo "       (Splunk, ELK, Wazuh) o para auditorías de compliance (CIS, ISO 27001)."
    echo "       Para el reporte en formato JSON, consulte: $REPORT_JSON"
    echo ""
  } > "$REPORT_TXT"

  cat "$REPORT_TXT"
  info "${GREEN}Reporte TXT generado: $REPORT_TXT${NC}"

  # --- 5.2 Reporte JSON (SIEM-ready) ---
  local json_report
  json_report=$(jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$hostname_info" \
    --arg kernel "$kernel_info" \
    --arg os "$os_info" \
    --arg uptime "$uptime_info" \
    --argjson alerts "$ALERTS" \
    --argjson warnings "$WARNINGS" \
    --argjson total "$total_findings" \
    --argjson findings "$JSON_FINDINGS" \
    '{
      "audit_id": "AUDIT-'"$TIMESTAMP_FILE"'",
      "timestamp": $timestamp,
      "host": {
        "hostname": $hostname,
        "kernel": $kernel,
        "os": $os,
        "uptime": $uptime
      },
      "summary": {
        "critical_alerts": $alerts,
        "warnings": $warnings,
        "total_findings": $total,
        "phases_completed": 5
      },
      "findings": $findings,
      "recommended_actions": [
        "Revisar manualmente alertas críticas marcadas como [ALERT]",
        "Verificar usuarios con UID 0 no autorizados",
        "Investigar IPs con alto volumen de intentos fallidos",
        "Auditar archivos SUID fuera del baseline conocido",
        "Confirmar que servicios habilitados en systemd sean legítimos"
      ],
      "compliance_mapping": {
        "CIS_v8": ["5.4.2", "5.4.3", "5.4.1", "4.1.3", "4.1.4"],
        "ISO_27001": ["A.9.2.1", "A.9.4.2", "A.12.4.1", "A.12.4.3"]
      }
    }')

  echo "$json_report" > "$REPORT_JSON"
  info "${GREEN}Reporte JSON generado: $REPORT_JSON${NC}"

  # --- 5.3 Resumen final en consola ---
  info "\n${GREEN}====================================================================${NC}"
  info "${GREEN}             AUDITORÍA COMPLETADA — 5 FASES EJECUTADAS              ${NC}"
  info "${GREEN}====================================================================${NC}"
  info "  Alertas críticas  : ${RED}$ALERTS${NC}"
  info "  Advertencias      : ${YELLOW}$WARNINGS${NC}"
  info "  Reporte TXT       : $REPORT_TXT"
  info "  Reporte JSON      : $REPORT_JSON"
  info "  Log de auditoría  : $LOG_FILE"
  info "${GREEN}====================================================================${NC}"
}

# ==============================================================================
# EJECUCIÓN PRINCIPAL
# ==============================================================================
main() {
  info "${BLUE}====================================================================${NC}"
  info "${BLUE}    AUDITORÍA DEFENSIVA DE SEGURIDAD v2.0 — 5 FASES                 ${NC}"
  info "${BLUE}    Inicio: $TIMESTAMP                                               ${NC}"
  info "${BLUE}====================================================================${NC}"

  run_phase1
  run_phase2
  run_phase3
  run_phase4
  run_phase5

  log "=== AUDITORÍA FINALIZADA: Alertas=$ALERTS Advertencias=$WARNINGS ==="
}

main "$@"
