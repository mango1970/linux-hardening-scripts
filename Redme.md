Script de Auditoría de Seguridad y Hardening en Linux / Linux Security Audit & Hardening Script
Este repositorio contiene una herramienta automatizada en Bash diseñada para la auditoría rápida de seguridad, la gestión proactiva de permisos críticos y el análisis defensivo de accesos dentro de sistemas operativos basados en Linux. Se enfoca en mitigar riesgos de persistencia y accesos no autorizados mediante configuraciones de diseño seguro.

🇪🇸 Versión en Español
🔍 Funcionalidades Principales
El script ejecuta un protocolo defensivo automatizado dividido en tres fases críticas:

Hardening de Permisos Esenciales: Verifica y restringe proactivamente los accesos a los archivos más sensibles de la gestión de identidades locales, asegurando que /etc/passwd mantenga permisos de lectura general (644) y que el archivo de hashes de contraseñas /etc/shadow quede completamente blindado solo para el superusuario (600), bajo la propiedad estricta de root.

Auditoría de Identidades y Privilegios: Procesa las cuentas locales para identificar configuraciones anómalas o maliciosas buscando usuarios no autorizados con UID 0 (privilegios de root ocultos). Además, muestra en tiempo real las sesiones de usuarios actualmente activas en la máquina.

Análisis Forense de Logs de Autenticación: Identifica de manera inteligente si el sistema es basado en Debian (auth.log) o RedHat (secure) y escanea las bitácoras para extraer los intentos de acceso fallidos más recientes, permitiendo la detección temprana de ataques de fuerza bruta.

🚀 Instrucciones de Uso
El script requiere privilegios de superusuario para poder auditar e interactuar de forma segura con los registros de autenticación del sistema.

Para ejecutarlo desde tu terminal:

Dar permisos de ejecución al archivo: chmod +x audit-security-essential.sh

Ejecutar la auditoría defensiva: sudo ./audit-security-essential.sh

📈 Valor Técnico y Buenas Prácticas
Control Estricto de Errores: Implementa el estándar normativo set -euo pipefail, obligando al script a detenerse inmediatamente ante variables no definidas o fallas en tuberías, evitando ejecuciones erráticas en servidores de producción.

Automatización Agnóstica: Es capaz de autorregular su ruta de logs dependiendo de la distribución de Linux detectada.

🇺🇸 English Version
🔍 Core Features
The script executes an automated defensive workflow divided into three critical security phases:

Essential Permissions Hardening: Proactively checks and restricts access to the most sensitive local identity management files. It ensures /etc/passwd maintains standard read permissions (644) and completely locks down the password hash storage file /etc/shadow exclusively for the superuser (600), enforcing strict ownership to root:root.

Identity & Privilege Auditing: Parses local system accounts to discover anomalous configuration baselines or persistence vectors by scanning for unauthorized users sharing UID 0 (hidden root privileges). It also outputs real-time active user sessions on the machine.

Authentication Log Forensic Analysis: Dynamically detects whether the host environment is Debian-based (auth.log) or RedHat-based (secure) and scans the logs to extract recent failed authentication attempts, providing early visibility into potential brute-force attacks.

🚀 Usage Instructions
The script requires superuser privileges to securely audit system configurations and read protected authentication logs.

To run it from your terminal:

Grant execution permissions: chmod +x audit-security-essential.sh

Run the defensive security audit: sudo ./audit-security-essential.sh

📈 Technical Value & Best Practices
Strict Error Handling: Implements the gold standard set -euo pipefail directive, forcing the shell to terminate immediately if any command or pipeline fails, preventing unintended execution paths on production servers.

Distro-Agnostic Automation: Intelligently resolves log locations depending on the detected Linux flavor.

📄 Licencia / License
Este proyecto está bajo la Licencia MIT / This project is licensed under the MIT License.