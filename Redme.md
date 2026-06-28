# Script de Auditoría de Seguridad y Hardening en Linux / Linux Security Audit & Hardening Script v2.0

Este repositorio contiene una herramienta automatizada en Bash para auditoría defensiva de seguridad en 5 fases: hardening de permisos, auditoría de usuarios y privilegios, análisis de logs con detección de fuerza bruta, detección de SUID/SGID anómalos y puertos, y generación de reportes TXT + JSON para integración SIEM.

---

## Espanol - Versión en Español

### Funcionalidades (5 Fases)

| Fase | Descripción |
|------|-------------|
| **1. Hardening de Permisos** | Verifica y corrige permisos de 6 archivos críticos (`/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`) con verificación previa (`stat -c %a`) y corrección de propietario `root:root`. |
| **2. Auditoría de Usuarios** | Detecta usuarios con UID 0 no autorizados, miembros de `sudo`/`wheel`, cuentas sin contraseña, shells interactivas en cuentas de sistema, usuarios activos y procesos root. |
| **3. Análisis de Logs y Persistencia** | Agregación de intentos fallidos por IP (detección de fuerza bruta), tareas cron de todos los usuarios, servicios systemd habilitados y accesos exitosos recientes. |
| **4. SUID, Puertos y Conexiones** | Detección de binarios SUID/SGID anómalos con baseline de legítimos, puertos en escucha (`ss -tulnp`), conexiones establecidas y directorios world-writable. |
| **5. Reportes SIEM-Ready** | Genera reporte dual: TXT legible + JSON estructurado con mapeo a CIS v8 e ISO 27001, listo para ingestión en Splunk, ELK o Wazuh. |

### Instrucciones de Uso

El script requiere privilegios de superusuario para auditar configuraciones del sistema y leer logs protegidos.

```bash
chmod +x linux-hardening-scripts.sh
sudo ./linux-hardening-scripts.sh            # Modo normal
sudo ./linux-hardening-scripts.sh --quiet    # Solo reportes y archivos
```

### Salidas Generadas

```
/var/log/hardening-audit/
├── audit-YYYYMMDD-HHMMSS.txt   # Reporte legible
├── audit-YYYYMMDD-HHMMSS.json  # JSON para SIEM (findings + compliance mapping)
└── hardening.log               # Log de cambios y eventos
```

### Buenas Prácticas Implementadas

- `set -euo pipefail` para control estricto de errores
- Verificación condicional de permisos antes de modificar (`stat -c %a`)
- Detección cross-distro de logs (`/var/log/auth.log` vs `/var/log/secure`)
- Fallback a `journalctl` para sistemas sin archivos de log tradicionales
- Baseline de binarios SUID legítimos para reducir falsos positivos
- Mapeo de hallazgos a controles CIS v8 e ISO 27001

---

## English Version

### Core Features (5 Phases)

| Phase | Description |
|-------|-------------|
| **1. Permission Hardening** | Verifies and fixes permissions on 6 critical files (`/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`) with pre-check (`stat -c %a`) and `root:root` ownership enforcement. |
| **2. User & Privilege Audit** | Detects unauthorized UID 0 users, `sudo`/`wheel` members, accounts without passwords, system accounts with interactive shells, active sessions, and root processes. |
| **3. Log Analysis & Persistence** | IP-aggregated failed login attempts (brute force detection), per-user cron tasks, enabled systemd services, and recent successful access logs. |
| **4. SUID, Ports & Connections** | Anomalous SUID/SGID binary detection against known-legitimate baseline, listening ports (`ss -tulnp`), established connections, and world-writable directories. |
| **5. SIEM-Ready Reports** | Dual output: human-readable TXT + structured JSON with CIS v8 and ISO 27001 compliance mapping, ready for Splunk, ELK, or Wazuh ingestion. |

### Usage

```bash
chmod +x linux-hardening-scripts.sh
sudo ./linux-hardening-scripts.sh            # Normal mode
sudo ./linux-hardening-scripts.sh --quiet    # Reports and files only
```

### Output Files

```
/var/log/hardening-audit/
├── audit-YYYYMMDD-HHMMSS.txt   # Human-readable report
├── audit-YYYYMMDD-HHMMSS.json  # SIEM-ready JSON (findings + compliance mapping)
└── hardening.log               # Change and event log
```

---

## Licencia / License

MIT License - Mauricio Nunez G.
