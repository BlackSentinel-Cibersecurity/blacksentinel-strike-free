# BlackSentinel Pentest Suite v4.0 - Manual Completo del Sistema

## Tabla de Contenidos

1. [Visión General del Sistema](#1-visión-general-del-sistema)
2. [Arquitectura](#2-arquitectura)
3. [Instalación](#3-instalación)
4. [Primera Ejecución y Configuración del Vault](#4-primera-ejecución-y-configuración-del-vault)
5. [Dashboard](#5-dashboard)
6. [Escaneo de Red](#6-escaneo-de-red)
7. [Escáner de Puertos](#7-escáner-de-puertos)
8. [Explorador Web](#8-explorador-web)
9. [Exploits](#9-exploits)
10. [Post-Exploitación](#10-post-exploitación)
11. [Ataque de Contraseñas](#11-ataque-de-contraseñas)
12. [Informes](#12-informes)
13. [Configuración](#13-configuración)
14. [Seguridad y Cifrado](#14-seguridad-y-cifrado)
15. [Solución de Problemas](#15-solución-de-problemas)
16. [War Exploit](#16-war-exploit)
17. [Ataques Inalámbricos](#17-ataques-inalámbricos)
18. [Ataques de Red](#18-ataques-de-red)
19. [Análisis Forense](#19-análisis-forense)
20. [Ingeniería Social](#20-ingeniería-social)
21. [Perfiles de Operador](#21-perfiles-de-operador)
22. [Autorización de Alcance](#22-autorización-de-alcance)
23. [Registro de Auditoría](#23-registro-de-auditoría)
24. [Notificaciones](#24-notificaciones)
25. [Limitación de Velocidad y Sigilo](#25-limitación-de-velocidad-y-sigilo)
26. [Base de Datos e Historial](#26-base-de-datos-e-historial)
27. [CI/CD y Despliegue](#27-cicd-y-despliegue)
28. [Pruebas](#28-pruebas)
29. [Listas de Palabras](#29-listas-de-palabras)

---

## 1. Visión General del Sistema

### ¿Qué es BlackSentinel Pentest Suite?

BlackSentinel Pentest Suite es una plataforma todo-en-uno de pruebas de penetración diseñada para profesionales de seguridad autorizados. Proporciona una interfaz gráfica unificada que integra herramientas de seguridad estándar de la industria (nmap, hydra, nikto, sqlmap, nuclei, masscan, etc.) con cifrado AES-256 incorporado para proteger todos los datos de escaneo y metadatos del operador.

### ¿Qué hace el sistema?

El sistema realiza:

- **Descubrimiento de Red**: Encontrar hosts activos en una red objetivo usando ping, SYN y escaneos TCP connect
- **Escaneo de Puertos**: Identificar puertos abiertos y servicios en ejecución en sistemas objetivo (desde los 1000 puertos comunes hasta los 65535 completos)
- **Reconocimiento de Aplicaciones Web**: Identificar servidores web, descubrir directorios, probar inyección SQL, escanear vulnerabilidades
- **Framework de Explotación**: Ejecutar scripts de vulnerabilidades nmap contra CVEs conocidos (EternalBlue, vsftpd, Struts2, etc.)
- **Post-Exploitación**: Enumerar sistemas comprometidos (usuarios, procesos, conexiones de red, hashes de contraseñas)
- **Ataques de Contraseñas**: Fuerza bruta SSH, FTP, HTTP, SMB, RDP, MySQL usando hydra con listas de palabras configurables
- **Generación de Informes**: Crear informes estructurados de pruebas de penetración con resumen ejecutivo, metodología, hallazgos y recomendaciones

### ¿Cómo funciona?

1. Inicias la aplicación (GUI Python/CustomTkinter)
2. El sistema te solicita crear o desbloquear un vault cifrado (AES-256)
3. Seleccionas un módulo de la barra lateral (Escaneo de Red, Escáner de Puertos, etc.)
4. Configuras el objetivo y los parámetros de escaneo
5. El sistema ejecuta la herramienta subyacente (nmap, hydra, etc.) en un hilo de fondo
6. Los resultados se transmiten en tiempo real a la consola de salida
7. Todos los resultados se cifran automáticamente y se guardan en `~/.blacksentinel-strike/vault/scans/`
8. Puedes generar informes a partir de los datos recopilados

### ¿Por qué existe?

- **Flujo de trabajo centralizado**: En vez de ejecutar 12+ herramientas desde terminales separadas, todo está en un solo lugar
- **Protección de datos**: Todos los resultados de escaneo y metadatos del operador están cifrados en reposo con AES-256
- **Auditoría**: Cada escaneo tiene marca de tiempo y está cifrado, creando un registro a prueba de manipulaciones
- **Productividad**: Transmisión de salida en tiempo real, ejecución de herramientas con un clic, generación automática de informes
- **Listo para despliegue**: Puede instalarse en servidores de la empresa para uso del equipo con Docker

### ¿Para quién es?

Probadores de penetración autorizados, operadores de red team y auditores de seguridad que necesitan realizar evaluaciones de seguridad autorizadas en sistemas para los que tienen autorización escrita para probar.

---

## 2. Arquitectura

```
blacksentinel-strike/
├── app.py                    # Aplicación GUI principal (1500+ líneas)
├── VERSION                   # Versión actual (4.0.0)
├── requirements.txt          # Dependencias de Python
├── Makefile                  # Comandos make (install, test, deploy, etc.)
├── deploy.sh                 # Script de despliegue automatizado
├── Dockerfile                # Despliegue con Docker
├── docker-compose.yml        # Orquestación Docker multi-servicio
├── MANUAL.md                 # Manual en inglés
├── MANUAL_ES.md              # Este manual en español
└── modules/
    ├── __init__.py
    ├── vault.py              # Motor de cifrado AES-256
    ├── network_utils.py      # IP jumper, DNS, randomización MAC
    ├── updater.py            # Sistema de actualización automática
    ├── recon.py              # Reconocimiento de red
    ├── web.py                # Análisis de aplicaciones web
    ├── exploits.py           # Framework de explotación (131 CVEs)
    ├── war_exploit.py        # Sistema automatizado de ataque multi-vector
    ├── bruteforce.py         # Ataques de fuerza bruta de contraseñas
    ├── postexploit.py        # Enumeración post-exploitación
    ├── forensic.py           # Análisis forense (disco, memoria, estego)
    ├── wireless.py           # Ataques de red inalámbrica (WiFi, BT, Zigbee, RFID)
    ├── network_attacks.py    # Ataques a nivel de red (ARP, DNS, MITM)
    ├── social_engineering.py # Herramientas de ingeniería social
    ├── database.py           # SQLite cifrado, historial, estadísticas
    ├── audit_log.py          # Logging persistente con rotación y pista de auditoría
    ├── operators.py          # Perfiles de operador, roles y permisos
    ├── scope.py              # Autorización de alcance y exclusiones
    ├── notifications.py      # Notificaciones por email y webhook
    ├── throttle.py           # Limitación de velocidad y sigilo
    ├── stealth.py            # Modos stealth (passive/quiet/moderate/aggressive)
    ├── reports.py            # Generación de informes
    ├── themes.py             # Definiciones de temas de la UI
    └── utils.py              # Utilidades compartidas
```

### Módulos Nuevos (v4.0+)

| Módulo | Propósito | Archivos Generados |
|--------|-----------|-------------------|
| `war_exploit.py` | Base de datos de 131 CVEs, pipeline de 7 etapas, ejecución paralela | `~/.blacksentinel-strike/war_results/` |
| `wireless.py` | WPA/WEP/WPS, PMKID, Evil Twin, Bluetooth, Zigbee, RFID, SDR | `~/.blacksentinel-strike/wireless/` |
| `network_attacks.py` | ARP spoofing, DNS poisoning, LLMNR/NBT-NS, WPAD, DHCP, VLAN hopping | `~/.blacksentinel-strike/net_attacks/` |
| `forensic.py` | Imagen de disco, análisis de memoria, esteganografía, cadena de custodia | `~/.blacksentinel-strike/forensic/` |
| `social_engineering.py` | 7 plantillas phishing, vishing, smishing, USB HID, QR, watering hole | `~/.blacksentinel-strike/social/` |
| `database.py` | SQLite cifrado, historial de hallazgos, estadísticas, exportación | `~/.blacksentinel-strike/database/blacksentinel.db` |
| `audit_log.py` | JSON estructurado, rotación (10MB × 10), pista de auditoría inmutable | `~/.blacksentinel-strike/logs/audit_*.json` |
| `operators.py` | 5 roles (admin/lead/analyst/viewer/auditor), API keys, sesiones | `~/.blacksentinel-strike/operators.enc` |
| `scope.py` | Autorización IP, CIDR, wildcard, dominio, exclusiones | `~/.blacksentinel-strike/scope.enc` |
| `notifications.py` | Email SMTP, webhooks Slack/Discord/Teams, filtrado por severidad | Config en `~/.blacksentinel-strike/` |
| `throttle.py` | Ventana deslizante, límites por objetivo, RateLimitException | Config en memoria |
| `stealth.py` | 4 niveles, decoys, jitter, randomización de paquetes | Config en memoria |

### Flujo de Datos

```
Entrada del Usuario (GUI)
    ↓
Manejador de Módulos (app.py)
    ↓
Ejecución de Herramientas (subprocess)
    ↓
Transmisión de Salida (threading + queue)
    ↓
Cifrado (vault.py - AES-256)
    ↓
Almacenamiento (~/.blacksentinel-strike/vault/scans/)
```

### Flujo de Cifrado

```
Contraseña Maestra
    ↓
PBKDF2-HMAC-SHA512 (1,000,000 iteraciones)
    ↓
Clave AES-256-CBC (32 bytes)
    ↓
Token Fernet (cifrar/descifrar)
```

---

## 3. Instalación

### Prerrequisitos

- macOS (probado en Apple Silicon) o Linux
- Python 3.10+
- Homebrew (macOS) o apt (Linux)
- Conexión a internet (para instalación inicial de herramientas)

### Instalación Paso a Paso

#### Paso 1: Clonar o descargar el proyecto

```bash
cd ~/hacks
# Si usas git:
git clone <url-del-repositorio> pentest-gui
# O copia la carpeta pentest-gui manualmente
cd pentest-gui
```

#### Paso 2: Instalación rápida con Make (recomendado)

```bash
# Instalación completa (dependencias + herramientas + configuración)
make install

# Despliegue completo (instalación + Docker + verificación)
make deploy
```

El Makefile ejecuta automáticamente:
- Verificación de Python 3.10+
- Instalación de dependencias de Python
- Instalación de herramientas de seguridad
- Creación de directorios del sistema (`~/.blacksentinel-strike/`)
- Configuración de listas de palabras
- Verificación de la instalación

#### Paso 2 (alternativo): Ejecutar el script de despliegue

```bash
bash deploy.sh
```

Este script:
- Verifica la versión de Python
- Instala pip si falta
- Instala dependencias de Python (customtkinter, psutil, requests, python-nmap, cryptography)
- Verifica/instala herramientas de seguridad (nmap, hydra, nikto, etc.)
- Crea el directorio del vault (`~/.blacksentinel-strike/vault/`)
- Crea un script de inicio rápido

#### Paso 3: Instalar herramientas de seguridad manualmente (si deploy.sh no instala alguna)

```bash
# macOS (Homebrew)
brew install nmap hydra nikto sqlmap gobuster masscan nuclei subfinder httpx ffuf

# WhatWeb (requiere Ruby)
brew install ruby
git clone --depth 1 https://github.com/urbanadventurer/whatweb.git /opt/homebrew/opt/whatweb
cat > /opt/homebrew/bin/whatweb << 'EOF'
#!/bin/bash
exec /opt/homebrew/opt/ruby/bin/ruby /opt/homebrew/opt/whatweb/whatweb "$@"
EOF
chmod +x /opt/homebrew/bin/whatweb

# Dirsearch (Python)
pip3 install --break-system-packages dirsearch

# Listas de palabras
sudo mkdir -p /usr/share/wordlists/dirb
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
    | sudo tee /usr/share/wordlists/dirb/common.txt > /dev/null
```

#### Paso 4: Instalar dependencias de Python (si deploy.sh no lo hizo)

```bash
pip3 install --break-system-packages -r requirements.txt
```

#### Paso 5: Verificar la instalación

```bash
# Verificar que todas las herramientas estén instaladas
for tool in nmap nikto sqlmap gobuster hydra whatweb masscan nuclei subfinder httpx ffuf dirsearch; do
    if command -v $tool >/dev/null 2>&1; then
        echo "[OK] $tool"
    else
        echo "[--] $tool NO INSTALADO"
    fi
done

# Verificar paquetes de Python
python3 -c "import customtkinter, psutil, requests, nmap, cryptography; print('Todos los paquetes Python OK')"
```

#### Paso 6: Iniciar la aplicación

```bash
python3 app.py
# O usa el launcher:
bash launch.sh
```

### Instalación con Docker (Despliegue en Servidor)

```bash
# Compilar
docker build -t blacksentinel-strike .

# Ejecutar (con reenvío de pantalla para GUI)
docker run -it --net=host -e DISPLAY=$DISPLAY blacksentinel-strike

# O ejecutar en modo headless y acceder vía VNC
docker run -it -p 5900:5900 blacksentinel-strike
```

### Verificación de Todas las Herramientas

Después de la instalación, ejecuta esta verificación:

```bash
python3 -c "
import shutil
tools = ['nmap','nikto','sqlmap','gobuster','hydra','whatweb','masscan','nuclei','subfinder','httpx','ffuf','dirsearch']
for t in tools:
    status = '[OK]' if shutil.which(t) else '[--]'
    print(f'{status} {t}')
"
```

Salida esperada: Las 12 herramientas muestran `[OK]`.

---

## 4. Primera Ejecución y Configuración del Vault

Cuando inicias la aplicación por primera vez:

1. Aparece un cuadro de diálogo: **"CONFIGURACIÓN DEL VAULT"**
2. Debes crear una **contraseña maestra** (mínimo 4 caracteres)
3. Esta contraseña cifra TODOS los datos: resultados de escaneo, configuración, metadatos
4. **ESTA CONTRASEÑA NO SE PUEDE RECUPERAR** - anótala en un lugar seguro

### Lo que el Vault Protege

| Tipo de Datos | Ubicación de Almacenamiento | Cifrado |
|---------------|----------------------------|---------|
| Resultados de escaneo | `~/.blacksentinel-strike/vault/scans/*.enc` | AES-256 |
| Configuración | `~/.blacksentinel-strike/vault/config.enc` | AES-256 |
| Metadatos (IP, MAC) | `~/.blacksentinel-strike/vault/metadata.enc` | AES-256 |
| Clave maestra | `~/.blacksentinel-strike/vault/master.key` | Derivada de PBKDF2 |
| Token de prueba | `~/.blacksentinel-strike/vault/test.token` | AES-256 |

### Ejecuciones Posteriores

En ejecuciones posteriores, se te solicitará ingresar tu contraseña maestra para desbloquear el vault. Todos tus resultados de escaneo y configuraciones anteriores serán restaurados.

---

## 5. Dashboard

El Dashboard es la primera pantalla que ves. Proporciona:

### Tarjeta de Plataforma
- Muestra: SO, release del kernel, tipo de máquina, versión de Python
- Propósito: Identificación rápida del sistema para documentación

### Tarjeta de Estado de Herramientas
- Lista las 12 herramientas de seguridad con estado `[OK]` (instalada) o `[--]` (faltante)
- Propósito: Verificar que las herramientas estén disponibles antes de iniciar escaneos

### Tarjeta de Información de Red
- Muestra: Hostname, IP Local
- Propósito: Identificar la posición de red de tu máquina atacante

### Acciones Rápidas
- **Escaneo de Red**: Saltar al módulo de Escaneo de Red
- **Escaneo de Puertos**: Saltar al módulo de Escáner de Puertos
- **Explorador Web**: Saltar al módulo de Explorador Web
- **Informes**: Saltar al módulo de Informes

### Info del Sistema (Barra Lateral)
- Uso de CPU y RAM en tiempo real
- Se actualiza cada 2 segundos

---

## 6. Escaneo de Red

**Propósito**: Descubrir hosts activos en una red objetivo.

### Cómo Funciona

1. Ingresa un objetivo (dirección IP o rango CIDR, ej: `192.168.1.0/24`)
2. Selecciona un tipo de escaneo
3. Haz clic en **Iniciar**
4. Los resultados se transmiten en tiempo real a la consola de salida
5. Los resultados se cifran automáticamente y se guardan

### Tipos de Escaneo

| Tipo | Bandera | Descripción | Velocidad | Sigilo |
|------|---------|-------------|-----------|--------|
| Ping | `-sn` | Solo descubrimiento de hosts (sin escaneo de puertos) | Rápido | Alto |
| SYN | `-sS` | Escaneo stealth SYN (half-open) | Medio | Alto |
| TCP Connect | `-sT` | Conexión TCP completa | Medio | Bajo |
| UDP | `-sU` | Escaneo de puertos UDP | Lento | Medio |
| Full | `-A` | Detección de SO + versión + scripts + traceroute | Lento | Bajo |

### Cuándo Usar Cada Tipo

- **Ping**: Reconocimiento inicial para encontrar hosts activos antes de un escaneo más profundo
- **SYN**: El más común para escaneo de puertos - rápido y sigiloso
- **TCP Connect**: Cuando SYN no funciona (sin root o redes filtradas)
- **UDP**: Para servicios como DNS, SNMP, DHCP que funcionan en UDP
- **Full**: Identificación detallada de un objetivo específico

### Objetivos de Ejemplo

```
192.168.1.1           # IP individual
192.168.1.0/24        # Red Clase C
10.0.0.1-10.0.0.254   # Rango de IPs
scanme.nmap.org       # Objetivo de prueba de Nmap
```

### Salida

Los resultados se guardan en:
- Salida de consola (tiempo real)
- `/tmp/ns_scan.txt` (texto plano)
- `~/.blacksentinel-strike/vault/scans/netscan_AAAAMMDD_HHMMSS.enc` (cifrado)

---

## 7. Escáner de Puertos

**Propósito**: Identificar puertos abiertos y servicios en ejecución en un sistema objetivo.

### Cómo Funciona

1. Ingresa un objetivo (IP o hostname)
2. Selecciona rango de puertos y opciones
3. Haz clic en **Iniciar**
4. Los resultados muestran puertos abiertos, servicios y versiones

### Opciones de Rango de Puertos

| Opción       | Descripción                          | Tiempo   | 
|--------------|--------------------------------------|----------|
| Common 1000  | Top 1000 puertos por defecto de nmap | ~10s     |
| Top 100      | Los 1000 puertos más comunes         | ~5s      |
| Top 50       | Los 50 puertos más comunes           | ~2s      |
| Full 65535   | Todos los puertos (lento)            | ~10min   |
| Custom       | Puertos especificados por el usuario | Variable |
| Masscan Fast | Todos los 65535 puertos vía masscan  | ~30s     |

### Opciones

- **Detección de servicios (-sV)**: Identifica versiones de servicios (ej: Apache 2.4.41)
- **Scripts por defecto (-sC)**: Ejecuta scripts por defecto de nmap para detección de vulnerabilidades

### Cuándo Usar

- **Common 1000**: Evaluación rápida de servicios expuestos
- **Full 65535**: Auditoría completa cuando el tiempo lo permite
- **Masscan Fast**: Descubrimiento rápido de todos los puertos, luego seguir con nmap en puertos encontrados
- **Custom**: Apuntar a puertos específicos (ej: `22,80,443,8080`)

### Flujo de Trabajo de Ejemplo

```
1. Masscan Fast en 192.168.1.0/24 -> encuentra puerto 80 abierto en 192.168.1.50
2. Escaneo de Puertos (Top 100 + Detección de servicios) en 192.168.1.50 -> identifica Apache 2.4.41
3. Explorador Web en http://192.168.1.50 -> análisis profundo de la app web
```

---

## 8. Explorador Web

**Propósito**: Analizar aplicaciones web en busca de vulnerabilidades y configuraciones erróneas.

### Herramientas Disponibles

| Herramienta | Propósito                     | Qué Encuentra                                   |
|-------------|-------------------------------|-------------------------------------------------|
| WhatWeb     | Identificación web            | Stack tecnológico, CMS, frameworks              |
| Gobuster    | Fuerza bruta de directorios   | Archivos/directorios ocultos                    |
| Nikto       | Escáner de servidor web       | Configuraciones erróneas, archivos peligrosos   |
| SQLMap      | Inyección SQL                 | Vulnerabilidades de inyección en bases de datos |
| FFuf        | Fuzzing web                   | Endpoints ocultos, parámetros                   |
| Dirsearch   | Descubrimiento de directorios | Archivos de respaldo, paneles admin             |
| Nuclei      | Escaneo de vulnerabilidades   | CVEs conocidos, configuraciones erróneas        |
| Subfinder   | Enumeración de subdominios    | Subdominios ocultos                             |

### Cómo Usar

1. Ingresa la URL del objetivo (ej: `http://192.168.1.50`)
2. Haz clic en el botón de la herramienta que quieres ejecutar
3. Los resultados se transmiten a la consola
4. Ejecuta múltiples herramientas para una cobertura completa

### Flujo de Trabajo Recomendado

```
1. WhatWeb        -> Identificar stack tecnológico
2. Subfinder      -> Encontrar subdominios
3. Gobuster       -> Descubrir directorios ocultos
4. Nikto          -> Escanear configuraciones erróneas
5. FFuf           -> Fuzzear endpoints ocultos
6. SQLMap         -> Probar inyección SQL
7. Nuclei         -> Escanear vulnerabilidades conocidas
```

### Detalles de Herramientas

#### WhatWeb
```bash
whatweb -a 3 <url>
```
- `-a 3`: Nivel de agresividad (1=silencioso, 3=agresivo)
- Encuentra: Tipo de CMS, librerías JavaScript, software del servidor, plugins

#### Gobuster
```bash
gobuster dir -u <url> -w /usr/share/wordlists/dirb/common.txt -t 10
```
- `-w`: Ruta de la lista de palabras
- `-t`: Número de hilos
- Encuentra: `/admin`, `/backup`, `/config.php`, etc.

#### Nikto
```bash
nikto -h <url>
```
- Escanea: 7000+ archivos/programas potencialmente peligrosos
- Verifica: Software obsoleto, configuraciones erróneas, archivos por defecto

#### SQLMap
```bash
sqlmap -u <url> --batch --crawl=2 --level=2
```
- `--batch`: Modo no interactivo
- `--crawl=2`: Rastrear 2 niveles de profundidad
- `--level=2`: Prueba más exhaustiva

#### FFuf
```bash
ffuf -u <url>/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403
```
- `-mc`: Coincidir códigos de estado HTTP
- La palabra FUZZ se reemplaza con entradas de la lista de palabras

#### Nuclei
```bash
nuclei -u <url> -severity low,medium,high,critical
```
- `-severity`: Filtrar por nivel de severidad
- Usa plantillas de vulnerabilidades curadas por la comunidad

---

## 9. Exploits

**Propósito**: Probar vulnerabilidades conocidas usando scripts de nmap.

### Exploits Disponibles

| Exploit             | Objetivo      | CVE/Descripción                                      |
|---------------------|---------------|------------------------------------------------------|
| EternalBlue         | SMB (445)     | MS17-010 - Ejecución remota de código en Windows SMB |
| vsftpd 2.3.4        | FTP (21)      | Ejecución de comandos de puerta trasera              |
| Apache Struts 2     | HTTP (8080)   | CVE-2017-5638 - RCE vía content-type                 |
| Tomcat Manager      | HTTP (8080)   | Fuerza bruta de credenciales del manager             |
| Samba CVE-2017-7494 | SMB (445)     | Ejecución remota de código vía share escribible      |
| WordPress XML-RPC   | HTTP (80)     | Fuerza bruta vía XML-RPC                             |
| SMB Vuln Scan       | SMB (139,445) | Todos los scripts de vulnerabilidades SMB            |
| SSH Audit           | SSH (22)      | Enumeración de algoritmos                            |
| FTP Anonymous       | FTP (21)      | Detección de login anónimo                           |
| HTTP Put            | HTTP (80,443) | Método PUT habilitado                                |

### Cómo Funciona

1. Ingresa la IP del objetivo
2. Selecciona el tipo de exploit
3. Haz clic en **Ejecutar**
4. nmap ejecuta el script correspondiente contra el objetivo
5. Los resultados muestran el estado de la vulnerabilidad

### Notas Importantes

- Estos son scripts de **detección**, no herramientas de explotación
- Verifican si una vulnerabilidad EXISTE, no la explotan activamente
- Siempre ten autorización escrita antes de ejecutar
- Los resultados se guardan en `/tmp/exploit.txt` y se cifran en el vault

---

## 10. Post-Exploitación

**Propósito**: Enumerar un sistema comprometido después de obtener acceso.

### Herramientas Disponibles

| Herramienta | Comando                        | Qué Muestra                           |
|-------------|--------------------------------|---------------------------------------|
| SystemInfo  | `uname -a` + `/etc/os-release` | Versión del SO, kernel, distribución  |
| Whoami      | `whoami && id && hostname`     | Usuario actual, UID/GID, hostname     |
| Processes   | `ps aux --sort=-%cpu`          | Procesos que más consumen CPU         |
| HashDump    | `cat /etc/shadow`              | Hashes de contraseñas (requiere root) |
| Network     | `netstat -tuln`                | Servicios de red en escucha           |

### Cuándo Usar

Después de obtener acceso shell a un objetivo:
1. **SystemInfo**: Identificar el SO para mayor explotación
2. **Whoami**: Determinar nivel de privilegios
3. **Processes**: Encontrar servicios en ejecución interesantes
4. **HashDump**: Extraer hashes de contraseñas para cracking offline
5. **Network**: Mapear conexiones de red internas

---

## 11. Ataque de Contraseñas

**Propósito**: Fuerza bruta de credenciales usando hydra.

### Protocolos Soportados

| Protocolo | Puerto | Servicio                 |
|-----------|--------|--------------------------|
| SSH       | 22     | Secure Shell             |
| FTP       | 21     | File Transfer Protocol   |
| HTTP      | 80     | Formularios de Login Web |
| SMB       | 445    | Windows File Sharing     |
| RDP       | 3389   | Escritorio Remoto        |
| MySQL     | 3306   | Base de Datos MySQL      |

### Cómo Funciona

1. Ingresa la IP/hostname del objetivo
2. Selecciona el protocolo
3. Ingresa el nombre de usuario
4. Selecciona la lista de palabras
5. Haz clic en **Atacar**

### Listas de Palabras

| Lista de Palabras | Tamaño               | Caso de Uso       |
|-------------------|----------------------|-------------------|
| rockyou.txt       | 14M contraseñas      | Propósito general |
| top-20.txt        | 20 contraseñas       | Prueba rápida     |
| common.txt        | 4K palabras          | Directorios web   |
| Custom            | Definida por usuario | Ataques dirigidos |

### Estructura del Comando Hydra

```bash
hydra -l <usuario> -P <lista-de-palabras> -s <puerto> -t 4 -f <objetivo> <protocolo>
```

- `-l`: Nombre de usuario
- `-P`: Lista de palabras de contraseñas
- `-s`: Número de puerto
- `-t`: Número de tareas paralelas (4 recomendado)
- `-f**: Detener al encontrar la primera contraseña

---

## 12. Informes

**Propósito**: Generar informes estructurados de pruebas de penetración.

### Tipos de Informe

| Tipo         | Audiencia      | Contenido                                       |
|--------------|----------------|-------------------------------------------------|
| Completo     | Equipo técnico | Hallazgos completos con evidencia               |
| Ejecutivo    | Gerencia       | Resumen de alto nivel, calificaciones de riesgo |
| Técnico      | Personal de TI | Vulnerabilidades detalladas y correcciones      |
| Cumplimiento | Auditores      | Mapeo a estándares de cumplimiento              |

### Secciones del Informe

1. **Resumen Ejecutivo**: Vista general de alto nivel de la evaluación
2. **Metodología**: Pasos seguidos durante la prueba
3. **Hallazgos**: Vulnerabilidades descubiertas con evidencia
4. **Recomendaciones**: Cómo corregir cada hallazgo

### Cómo Generar

1. Ingresa el nombre del proyecto
2. Selecciona el tipo de informe
3. Marca las secciones deseadas
4. Haz clic en **Generar**
5. El informe aparece en la ventana de vista previa
6. Se guarda en `/tmp/report_<nombre>.txt`

---

## 13. Configuración

La página de Configuración controla toda la configuración del sistema.

### Estado del Vault
- Muestra estado BLOQUEADO/DESBLOQUEADO
- **Cambiar Contraseña**: Cambiar la contraseña maestra de cifrado

### Información de Red Actual
- Muestra IP actual, direcciones MAC, estado de interfaces
- **Actualizar**: Actualizar información de red

### IP Jumper (Rotación Automática)
- **Habilitar IP Jumper**: Cambiar la IP automáticamente en intervalos
- **Intervalo**: Segundos entre rotaciones (por defecto: 300)
- **Método**:
  - `dhcp`: Liberar y renovar contrato DHCP
  - `mac_rotate`: Cambiar dirección MAC primero, luego renovar DHCP
- **Interfaz**: Interfaz de red a rotar (ej: `en0`)
- **Rotar Ahora**: Activar rotación inmediata
- **Detener Jumper**: Detener rotación automática

### Configuración DNS
- **DNS Primario/Secundario**: Configurar servidores DNS personalizados
- **Predefinidos**: Google (8.8.8.8), Cloudflare (1.1.1.1), Quad9 (9.9.9.9), OpenDNS
- **Aplicar DNS**: Establecer los servidores DNS configurados
- **Restaurar Predeterminado**: Restablecer al DNS asignado por DHCP

### Randomización de Dirección MAC
- **Randomizar MAC al inicio**: Cambiar MAC automáticamente al iniciar la app
- **Interfaz**: Qué interfaz randomizar
- **Randomizar Ahora**: Cambiar MAC inmediatamente

### Configuración de Cifrado
- **Cifrar resultados de escaneo automáticamente**: Cifrar toda la salida de escaneo
- **Cifrar metadatos automáticamente**: Cifrar metadatos de red al salir
- Info del algoritmo: AES-256-CBC, PBKDF2 1M iteraciones

### Info del Operador
- **Empresa**: Nombre de tu organización (para informes)
- **Operador**: Tu nombre (para informes)
- **Objetivos Autorizados**: Lista separada por comas de objetivos autorizados

### Actualización del Sistema
- **Versión Actual**: Número de versión mostrado
- **Buscar Actualizaciones**: Consultar servidor remoto por actualizaciones
- **Instalar Deps**: Reinstalar/actualizar dependencias de Python
- **Copia de Seguridad Ahora**: Crear respaldo de la aplicación
- **Ver Registro**: Mostrar historial de actualizaciones
- **URL Fuente de Actualización**: URL del servidor de actualizaciones
- **Aplicar Actualización**: Instalar actualización desde ruta local

### Guardar/Exportar/Destruir
- **GUARDAR TODA LA CONFIGURACIÓN**: Persistir toda la configuración en el vault cifrado
- **Exportar Respaldo Cifrado**: Exportar configuración como archivo cifrado
- **Destruir Vault**: Eliminar permanentemente todos los datos cifrados (requiere escribir "DESTROY")

---

## 14. Seguridad y Cifrado

### Detalles del Cifrado

| Parámetro           | Valor |
|---------------------|--------------------------------|
| Algoritmo           | AES-256-CBC                    |
| Derivación de Clave | PBKDF2-HMAC-SHA512             |
| Iteraciones         | 1,000,000 (OWASP 2023)         |
| Salt                | 16 bytes (aleatorio por vault) |
| Tamaño de Clave     | 256 bits (32 bytes)            |
| Librería            | `cryptography` (Python)        |

### Qué se Cifra

| Datos                            | Cuándo                  | Dónde |
|----------------------------------|-------------------------|---------------------------------|
| Resultados de escaneo de red     | Después de cada escaneo | `~/.blacksentinel-strike/vault/scans/`       |
| Resultados de escaneo de puertos | Después de cada escaneo | `~/.blacksentinel-strike/vault/scans/`       |
| Resultados de herramientas web   | Después de cada escaneo | `~/.blacksentinel-strike/vault/scans/`       |
| Resultados de exploits           | Después de cada escaneo | `~/.blacksentinel-strike/vault/scans/`       |
| Configuración                    | Al guardar              | `~/.blacksentinel-strike/vault/config.enc`   |
| Metadatos de red                 | Al salir de la app      | `~/.blacksentinel-strike/vault/metadata.enc` |

### Seguridad del Vault

- La contraseña maestra nunca se almacena - solo se guarda la clave derivada
- Cada vault tiene un salt único de 16 bytes
- 1,000,000 iteraciones de PBKDF2 hacen que la fuerza bruta sea extremadamente lenta
- El token de prueba verifica la contraseña sin exponer la clave
- Permisos de archivo establecidos en 600 (solo el propietario lee/escribe)

### Privacidad de Red

- **IP Jumper**: Cambia tu IP periódicamente para evitar rastreo
- **Randomización MAC**: Cambia la dirección de hardware para prevenir fingerprinting del dispositivo
- **Cambio DNS**: Usa DNS enfocados en privacidad (Cloudflare, Quad9)

### Módulos de Seguridad Adicionales

| Módulo         | Propósito                       | Detalle                                                    |
|----------------|---------------------------------|------------------------------------------------------------|
| `operators.py` | Control de acceso por roles     | 5 roles: admin, lead, analyst, viewer, auditor             |
| `scope.py`     | Autorización de alcance         | Validación IP/CIDR/dominio, exclusiones, whitelists        |
| `audit_log.py` | Registro de auditoría inmutable | JSON estructurado, rotación automática, hash de integridad |
| `database.py`  | Base de datos cifrada           | SQLite cifrado en reposo, historial de hallazgos           |
| `stealth.py`   | Modos de sigilo                 | 4 niveles: passive, quiet, moderate, aggressive            |
| `throttle.py`  | Limitación de velocidad         | Ventana deslizante, límites por objetivo                   |

---

## 15. Solución de Problemas

### Problemas Comunes

#### "Falló la configuración del vault"
- Verifica permisos de escritura en `~/.blacksentinel-strike/vault/`
- Asegúrate de tener suficiente espacio en disco
- Intenta eliminar `~/.blacksentinel-strike/vault/` y reiniciar

#### "Contraseña incorrecta"
- La contraseña distingue mayúsculas y minúsculas
- Mínimo 4 caracteres
- Si quedas bloqueado, elimina el vault: `rm -rf ~/.blacksentinel-strike/vault/`

#### Herramienta no encontrada `[--]`
```bash
# Instalar herramienta faltante
brew install <nombre-herramienta>

# Para whatweb
brew install ruby
git clone --depth 1 https://github.com/urbanadventurer/whatweb.git /opt/homebrew/opt/whatweb
```

#### El escaneo se cuelga o expira
- El objetivo puede ser inalcanzable
- El firewall puede estar bloqueando
- Intenta un tipo de escaneo más simple (Ping primero)
- Verifica la conectividad de red

#### "Permiso denegado" en cambios DNS/MAC
- Estas operaciones requieren sudo
- La app solicitará tu contraseña del sistema

#### La GUI no se muestra
```bash
# Asegúrate de que DISPLAY esté configurado (Linux)
export DISPLAY=:0

# Instala XQuartz (macOS)
brew install --cask xquartz
```

### Obtener Ayuda

- Revisa la página de **Ayuda** en la barra lateral de la aplicación
- Revisa la salida de escaneo en la **Consola** en la parte inferior de la pantalla
- Verifica el estado de las herramientas en el **Dashboard**

### Ubicaciones de Archivos

| Archivo                          | Propósito                          |
|----------------------------------|------------------------------------|
| `~/.blacksentinel-strike/vault/`              | Todos los datos cifrados           |
| `~/.blacksentinel-strike/vault/scans/`        | Resultados de escaneo cifrados     |
| `~/.blacksentinel-strike/vault/config.enc`    | Configuración cifrada              |
| `~/.blacksentinel-strike/vault/metadata.enc`  | Metadatos cifrados                 |
| `~/.blacksentinel-strike/database/blacksentinel.db` | Base de datos SQLite cifrada       |
| `~/.blacksentinel-strike/logs/audit_*.json`   | Registros de auditoría             |
| `~/.blacksentinel-strike/operators.enc`       | Perfiles de operador cifrados      |
| `~/.blacksentinel-strike/scope.enc`           | Autorizaciones de alcance cifradas |
| `~/.blacksentinel-strike/war_results/`        | Resultados de War Exploit          |
| `~/.blacksentinel-strike/wireless/`           | Resultados de ataques inalámbricos |
| `~/.blacksentinel-strike/net_attacks/`        | Resultados de ataques de red       |
| `~/.blacksentinel-strike/forensic/`           | Evidencia forense                  |
| `~/.blacksentinel-strike/social/`             | Campañas de ingeniería social      |
| `~/.blacksentinel-strike/wordlists/`          | Listas de palabras del sistema     |
| `/tmp/*.txt`                     | Salidas de escaneo en texto plano  |
| `/tmp/report_*.txt`              | Informes generados                 |

---

## Tarjeta de Referencia Rápida

```
INICIO:        python3 app.py
INSTALACIÓN:   make install
DESPLIEGUE:    make deploy
PRUEBAS:       make test
VAULT:         Crear contraseña en primera ejecución, ingresar en ejecuciones posteriores
ESCANEOS:      Seleccionar módulo -> Configurar -> Iniciar -> Resultados cifrados automáticamente
WAR EXPLOIT:   python3 -m modules.war_exploit --target <ip> --cve <CVE-ID> --profile <perfil>
INALÁMBRICO:   Seleccionar pestaña Inalámbrico -> Interfaz -> Objetivo -> Atacar
ATAQUES RED:   Seleccionar pestaña Red -> Tipo de ataque -> Objetivo -> Ejecutar
FORENSE:       Seleccionar pestaña Forense -> Tipo de análisis -> Fuente -> Analizar
SOCIAL:        Seleccionar pestaña Social -> Plantilla -> Configurar -> Campaña
OPERADORES:    Administrar en Configuración -> Perfiles de Operador
ALCANCE:       Configurar en Configuración -> Autorización de Alcance
NOTIFICAR:     Configurar SMTP/webhooks en Configuración -> Notificaciones
CONFIGURAR:    Configurar rotación IP, DNS, MAC, cifrado, info del operador
INFORMES:      Generar después de escaneos -> Seleccionar secciones -> Exportar
DOCKER:        docker-compose up -d
BASE DATOS:    python3 -c "from modules.database import BlackSentinelDB; BlackSentinelDB().get_stats()"
AUDITORÍA:     ls ~/.blacksentinel-strike/logs/audit_*.json
SISTEMAS:      ls ~/.blacksentinel-strike/logs/syslog_*.json
```

---

## 16. War Exploit

**Propósito**: Sistema automatizado de ataque multi-vector con base de datos de 131 CVEs y pipeline de 7 etapas.

### Qué Hace

War Exploit es un framework de explotación automatizado que:
- Contiene una base de datos de **131 CVEs** categorizados por severidad
- Soporta **7 tipos de objetivo**: web, SMB, SSH, FTP, SNMP, RDP, database
- Ejecuta un **pipeline de 7 etapas**: recon, fingerprinting, CVE matching, validation, exploitation, post-exploit, reporting
- Permite **ejecución paralela** de hasta 10 ataques simultáneos
- Genera reportes automatizados con evidencia de cada hallazgo

### Cómo Usarlo

#### Paso 1: Seleccionar el módulo War Exploit

En la barra lateral, selecciona **War Exploit** o ejecuta desde línea de comandos:

```bash
python3 -m modules.war_exploit --target <IP_OBJETIVO>
```

#### Paso 2: Configurar el objetivo

1. Ingresa la IP o hostname del objetivo
2. Selecciona el tipo de objetivo (web, SMB, SSH, etc.)
3. El sistema escaneará automáticamente los puertos relevantes

#### Paso 3: Seleccionar perfil de ataque

| Perfil       | Descripción                                | Riesgo |
|--------------|--------------------------------------------|--------|
| `stealth`    | Solo detección, sin explotación activa     | Bajo   |
| `standard`   | Detección + validación de vulnerabilidades | Medio  |
| `aggressive` | Explotación completa + post-exploitation   | Alto   |
| `audit`      | Auditoría completa con cadena de custodia  | Medio  |

#### Paso 4: Ejecutar el pipeline

```bash
# Ejecución completa con perfil estándar
python3 -m modules.war_exploit --target 192.168.1.50 --profile standard

# Ejecución específica de un CVE
python3 -m modules.war_exploit --target 192.168.1.50 --cve CVE-2017-0143

# Ejecución paralela de múltiples objetivos
python3 -m modules.war_exploit --targets-file targets.txt --parallel 5 --profile stealth
```

### Pipeline de 7 Etapas

```
1. Reconocimiento      → Descubrimiento de servicios y puertos
2. Fingerprinting      → Identificación precisa de versiones
3. CVE Matching        → Cruze con base de datos de 131 CVEs
4. Validación          → Prueba no destructiva de la vulnerabilidad
5. Explotación         → Explotación controlada (si perfil lo permite)
6. Post-Exploitación   → Enumeración del sistema comprometido
7. Reporte             → Generación de evidencia y hallazgos
```

### Base de Datos de CVEs

| Categoría | CVEs Incluidos                                         | Severidad |
|-----------|--------------------------------------------------------|-----------|
| SMB       | EternalBlue, EternalRomance, EternalChampion, SMBGhost | Crítica   |
| Web       | Struts2, Apache, Tomcat, WordPress, Jenkins            | Alta      |
| SSH       | User enumeration, weak ciphers, CVEs de OpenSSH        | Media     |
| FTP       | vsftpd backdoor, ProFTPD, Pure-FTPd                    | Alta      |
| SNMP      | Community strings, RCE                                 | Media     |
| RDP       | BlueKeep, DejaBlue, DoS                                | Crítica   |
| Database  | MySQL, PostgreSQL, MongoDB, Redis                      | Alta      |

### Ejemplo de Uso Completo

```bash
# 1. Escaneo rápido del objetivo
python3 -m modules.recon --target 192.168.1.0/24

# 2. War Exploit contra un host encontrado
python3 -m modules.war_exploit --target 192.168.1.50 --profile standard --output war_results.json

# 3. Revisar resultados
cat war_results.json | python3 -m json.tool
```

### Configuración

| Parámetro     | Valor por Defecto         | Descripción                        |
|---------------|---------------------------|------------------------------------|
| `parallel`    | 5                         | Número máximo de ataques paralelos |
| `timeout`     | 300                       | Timeout por CVE (segundos)         |
| `profile`     | `standard`                | Perfil de ejecución por defecto    |
| `output_dir`  | `~/.blacksentinel-strike/war_results/` | Directorio de resultados           |
| `auto_report` | `true`                    | Generar reporte automáticamente    |

---

## 17. Ataques Inalámbricos

**Propósito**: Ataques completos a redes inalámbricas: WiFi (WPA/WEP/WPS), Bluetooth, Zigbee, RFID y SDR.

### Qué Hace

El módulo de ataques inalámbricos proporciona:
- **WiFi**: Ataques WPA/WPA2/WPA3, WEP, WPS, PMKID, Evil Twin, Karma
- **Bluetooth**: Escaneo BLE, ataque KNOB, BlueBorne, sniffing
- **Zigbee**: Captura de paquetes, replay attacks, key extraction
- **RFID**: Lectura/escritura de tags, clonación, fuzzing
- **SDR (Software Defined Radio)**: Análisis de señales de radio, protocolos custom

### Cómo Usarlo

#### Paso 1: Seleccionar interfaz inalámbrica

```bash
# Listar interfaces disponibles
iwconfig
# o en macOS:
system_profiler SPAirPortDataType
```

En la GUI, selecciona la interfaz del menú desplegable (ej: `wlan0`, `en0`, `wlp2s0`).

#### Paso 2: Seleccionar tipo de ataque

##### Ataques WiFi

| Tipo de Ataque | Descripción                  | Requisitos          |
|----------------|------------------------------|---------------------|
| WPA Handshake  | Captura del 4-way handshake  | Cliente conectado   |
| PMKID Attack   | Ataque sin cliente (solo AP) | PMKID habilitado    |
| Evil Twin      | AP falso con el mismo SSID   | Tarjeta compatible  |
| WEP Cracking   | Captura de IVs + cracking    | Red WEP activa      |
| WPS Reaver     | Ataque PIN a WPS             | WPS habilitado      |
| Karma Attack   | Redirection a AP falso       | Framework Mana      |

##### Ataques Bluetooth

| Tipo de Ataque | Descripción                    | Herramienta            |
|----------------|--------------------------------|------------------------|
| BLE Scanning   | Escaneo de dispositivos BLE    | `hcitool`, `bettercap` |
| KNOB Attack    | Reducción de entropía de clave | Custom script          |
| BlueBorne      | Explotación remota sin pairing | Custom exploits        |
| Sniffing       | Captura de tráfico BT          | `ubertooth`            |

##### Ataques RFID

| Tipo de Ataque | Descripción                 | Herramienta          |
|----------------|-----------------------------|----------------------|
| Read/Write     | Lectura y escritura de tags | `libnfc`, `proxmark` |
| Clonación      | Copiar tag a otro tag       | `proxmark3`          |
| Fuzzing        | Envío de datos aleatorios   | Custom script        |

#### Paso 3: Ejecutar el ataque

```bash
# WPA Handshake capture
python3 -m modules.wireless --interface wlan0 --target "MyNetwork" --attack wpa-handshake

# PMKID Attack
python3 -m modules.wireless --interface wlan0 --target "MyNetwork" --attack pmkid

# Evil Twin
python3 -m modules.wireless --interface wlan0 --ssid "FreeWiFi" --attack evil-twin

# Bluetooth scanning
python3 -m modules.wireless --interface hci0 --attack ble-scan

# RFID read
python3 -m modules.wireless --interface usb0 --attack rfid-read
```

### Opciones de Ataque WiFi

| Opción       | Descripción                         | Valor por Defecto                  |
|--------------|-------------------------------------|------------------------------------|
| `--channel`  | Canal específico a escanear         | Auto                               |
| `--bssid`    | BSSID del AP objetivo               | Auto                               |
| `--wordlist` | Lista de palabras para cracking     | `~/.blacksentinel-strike/wordlists/rockyou.txt` |
| `--deauth`   | Número de paquetes de deauth        | 5                                  |
| `--timeout`  | Tiempo máximo de captura (segundos) | 60                                 |
| `--power`    | Potencia de transmisión (dBm)       | 20                                 |

### Configuración

| Parámetro      | Valor por Defecto      | Descripción                            |
|----------------|------------------------|----------------------------------------|
| `monitor_mode` | `true`                 | Habilitar modo monitor automáticamente |
| `auto_deauth`  | `false`                | Deauth automático después de captura   |
| `channel_hop`  | `true`                 | Saltar entre canales en escaneo        |
| `output_dir`   | `~/.blacksentinel-strike/wireless/` | Directorio de resultados               |

---

## 18. Ataques de Red

**Propósito**: Ataques a nivel de red: ARP spoofing, DNS poisoning, LLMNR/NBT-NS, WPAD, DHCP, VLAN hopping y servidores rogue.

### Qué Hace

El módulo de ataques de red permite:
- **ARP Spoofing**: Envenenamiento de tablas ARP para MITM
- **DNS Poisoning**: Inyección de registros DNS falsos
- **LLMNR/NBT-NS Poisoning**: Captura de credenciales en redes Windows
- **WPAD Poisoning**: Explotación de proxy automático
- **DHCP Starvation/Spoofing**: Agotamiento de pool DHCP y servidores rogue
- **VLAN Hopping**: Acceso a VLANs no autorizadas
- **Servidores Rogue**: DNS, DHCP, SMB, HTTP falsos

### Cómo Usarlo

#### Paso 1: Configurar la interfaz de red

```bash
# Verificar interfaz
ip addr show
# Habilitar IP forwarding (requerido para MITM)
sudo sysctl -w net.ipv4.ip_forward=1
```

#### Paso 2: Seleccionar tipo de ataque

| Ataque          | Objetivo     | Descripción                              |
|-----------------|--------------|------------------------------------------|
| ARP Spoofing    | LAN local    | Redirigir tráfico vía envenenamiento ARP |
| DNS Poisoning   | LAN/Internet | Responder consultas DNS con IP falsa     |
| LLMNR/NBT-NS    | Red Windows  | Capturar hashes NTLMv2                   |
| WPAD Poisoning  | Red Windows  | Forzar configuración de proxy            |
| DHCP Starvation | LAN          | Agotar pool de IPs DHCP                  |
| DHCP Spoofing   | LAN          | Servidor DHCP falso                      |
| VLAN Hopping    | Switch       | Acceso a VLANs trunk                     |

#### Paso 3: Ejecutar el ataque

```bash
# ARP Spoofing
python3 -m modules.network_attacks --interface en0 --target 192.168.1.1 --gateway 192.168.1.254 --attack arp-spoof

# DNS Poisoning
python3 -m modules.network_attacks --interface en0 --attack dns-poison --fake-ip 10.10.10.1

# LLMNR/NBT-NS Poisoning
python3 -m modules.network_attacks --interface en0 --attack llmnr-poison

# DHCP Starvation
python3 -m modules.network_attacks --interface en0 --attack dhcp-starve

# VLAN Hopping
python3 -m modules.network_attacks --interface en0 --attack vlan-hop --target-vlan 100
```

### Parámetros de Ataque

| Parámetro      | Descripción                    | Valor por Defecto |
|----------------|--------------------------------|-------------------|
| `--interface`  | Interfaz de red                | `eth0`            |
| `--target`     | IP del gateway/objetivo        | Requerido         |
| `--duration`   | Duración del ataque (segundos) | 60                |
| `--spoof-mac`  | MAC falsa para spoofing        | Aleatoria         |
| `--dns-server` | IP del servidor DNS falso      | `10.10.10.1`      |
| `--pool-size`  | Tamaño del pool DHCP falso     | 50                |

### Herramientas Integradas

| Herramienta | Uso                     | Comando                                 |
|-------------|-------------------------|-----------------------------------------|
| `arpspoof`  | ARP spoofing nativo     | `arpspoof -i en0 -t <target> <gateway>` |
| `bettercap` | Framework MITM completo | `bettercap -iface en0 -eval "..."`      |
| `responder` | LLMNR/NBT-NS poisoning  | `responder -I en0 -wrf`                 |
| `dnsmasq`   | Servidor DNS/DHCP falso | `dnsmasq -C dnsmasq.conf`               |
| `yersinia`  | Ataques a protocolos L2 | `yersinia dhcp -attack 1`               |

### Configuración

| Parámetro       | Valor por Defecto         | Descripción                                  |
|-----------------|---------------------------|----------------------------------------------|
| `ip_forward`    | `true`                    | Habilitar forwarding automáticamente         |
| `auto_redirect` | `true`                    | Configurar iptables para redirigir tráfico   |
| `log_captures`  | `true`                    | Registrar todas las capturas de credenciales |
| `output_dir`    | `~/.blacksentinel-strike/net_attacks/` | Directorio de resultados                     |

---

## 19. Análisis Forense

**Propósito**: Análisis forense de disco, memoria, esteganografía, navegador/email y cadena de custodia.

### Qué Hace

El módulo forense proporciona:
- **Imagen de Disco**: Creación y análisis de imágenes de disco bit a bit
- **Análisis Forense de Memoria**: Extracción de procesos, conexiones, contraseñas de volcados de memoria
- **Esteganografía**: Detección y extracción de datos ocultos en imágenes/audio/video
- **Análisis de Navegador**: Extracción de historial, cookies, contraseñas de navegadores
- **Análisis de Email**: Extracción de adjuntos, metadatos, cabezeras
- **Cadena de Custodia**: Registro criptográfico de integridad de evidencia

### Cómo Usarlo

#### Paso 1: Seleccionar tipo de análisis

| Tipo de Análisis | Fuente                | Herramientas                   |
|------------------|-----------------------|--------------------------------|
| Imagen de Disco  | Dispositivo de bloque | `dd`, `dc3dd`, `guymager`      |
| Memoria          | Volcado de RAM        | `volatility`, `rekall`         |
| Esteganografía   | Archivos multimedia   | `steghide`, `zsteg`, `binwalk` |
| Navegador        | Perfiles de usuario   | Custom scripts                 |
| Email            | Archivos .eml/.pst    | `libpff`, `readpst`            |

#### Paso 2: Ejecutar el análisis

```bash
# Crear imagen de disco
python3 -m modules.forensic --source /dev/disk2 --output /forensics/evidence.img --type disk-image

# Análisis de memoria
python3 -m modules.forensic --source memory.dmp --type memory --profile Win10x64

# Detección esteganografía
python3 -m modules.forensic --source image.png --type stego --tool steghide

# Análisis de navegador
python3 -m modules.forensic --source "/Users/*/Library/Safari" --type browser --browser safari

# Extracción de email
python3 -m modules.forensic --source mailbox.pst --type email
```

### Herramientas Forenses

| Herramienta  | Propósito                     | Comando                                           |
|--------------|-------------------------------|---------------------------------------------------|
| `dd`         | Creación de imágenes de disco | `dd if=/dev/disk2 of=evidence.img bs=4M`          |
| `dc3dd`      | dd con hash integrado         | `dc3dd if=/dev/disk2 of=evidence.img hash=sha256` |
| `volatility` | Análisis forense de memoria   | `volatility -f memory.dmp imageinfo`              |
| `steghide`   | Esteganografía en JPEG/BMP    | `steghide extract -sf image.jpg`                  |
| `binwalk`    | Análisis de firmware/embebido | `binwalk -e image.bin`                            |
| `zsteg`      | Esteganografía en PNG/BMP     | `zsteg image.png`                                 |

### Cadena de Custodia

```bash
# Registrar evidencia con hash
python3 -m modules.forensic --register-evidence \
    --file evidence.img \
    --operator "Juan Perez" \
    --case "CASE-2024-001" \
    --description "Imagen de disco del servidor web"

# Verificar integridad
python3 -m modules.forensic --verify-evidence \
    --file evidence.img \
    --hash "sha256:abc123..."
```

### Metadatos de Cadena de Custodia

| Campo         | Descripción                      |
|---------------|----------------------------------|
| `case_id`     | Identificador del caso           |
| `operator`    | Nombre del operador              |
| `timestamp`   | Fecha/hora de captura (ISO 8601) |
| `hash_sha256` | Hash SHA-256 de la evidencia     |
| `hash_md5`    | Hash MD5 de la evidencia         |
| `source`      | Dispositivo/archivo de origen    |
| `description` | Descripción de la evidencia      |
| `tool`        | Herramienta utilizada            |

### Configuración

| Parámetro            | Valor por Defecto      | Descripción |
|----------------------|------------------------|----------------------------------------------|
| `hash_algorithm`     | `sha256`               | Algoritmo de hash para evidencia             |
| `output_dir`         | `~/.blacksentinel-strike/forensic/` | Directorio de evidencia                      |
| `chain_of_custody`   | `true`                 | Registrar cadena de custodia automáticamente |
| `verify_on_complete` | `true`                 | Verificar hashes al finalizar                |

---

## 20. Ingeniería Social

**Propósito**: Herramientas de ingeniería social: phishing, vishing, smishing, USB HID, códigos QR y watering hole.

### Qué Hace

El módulo de ingeniería social proporciona:
- **7 plantillas de phishing**: Corporate, Bank, Social Media, IT Support, Shipping, Healthcare, Government
- **Vishing**: Scripts automatizados de llamadas de voz
- **Smishing**: Mensajes SMS de phishing
- **USB HID**: Ataques de teclado emulador (Rubber Ducky)
- **Códigos QR**: Generación de QR maliciosos con tracking
- **Watering Hole**: Inyección de código en sitios frecuentados

### Cómo Usarlo

#### Paso 1: Seleccionar tipo de campaña

| Tipo          | Descripción             | Canal      |
|---------------|-------------------------|------------|
| Phishing Web  | Páginas de login falsas | HTTP/HTTPS |
| Vishing       | Llamadas automatizadas  | Voz        |
| Smishing      | Mensajes SMS            | SMS        |
| USB HID       | Ataques de teclado      | USB        |
| QR Code       | Códigos QR rastreables  | Físico     |
| Watering Hole | Infección de sitios web | Web        |

#### Paso 2: Configurar la campaña

##### Phishing Web

```bash
# Seleccionar plantilla
python3 -m modules.social_engineering --type phishing \
    --template corporate \
    --target-url http://192.168.1.50:8080 \
    --tracking-id CAMPAIGN-001

# Plantillas disponibles
--template corporate      # Portal corporativo
--template bank           # Banco en línea
--template social         # Redes sociales
--template it-support     # Soporte de TI
--template shipping       # Servicio de paquetería
--template healthcare     # Portal de salud
--template government     # Portal gubernamental
```

##### Vishing

```bash
# Script de vishing
python3 -m modules.social_engineering --type vishing \
    --script "Soporte de TI - Actualización de seguridad" \
    --target-list targets.txt \
    --caller-id "+1234567890"
```

##### USB HID

```bash
# Generar payload para Rubber Ducky
python3 -m modules.social_engineering --type usb-hid \
    --payload reverse-shell \
    --output usb_payload.bin \
    --target-os windows
```

##### Códigos QR

```bash
# Generar QR con tracking
python3 -m modules.social_engineering --type qr \
    --url "http://attacker.com/phish" \
    --output qr_phish.png \
    --track-clicks
```

### Plantillas de Phishing

| Plantilla    | Descripción                 | Elementos                   |
|--------------|-----------------------------|-----------------------------|
| `corporate`  | Portal corporativo de login | Logo, formularios, branding |
| `bank`       | Banco en línea              | Formulario de cuenta, OTP   |
| `social`     | Redes sociales              | Login social, permisos      |
| `it-support` | Soporte de TI               | Ticket, credenciales        |
| `shipping`   | Paquetería                  | Tracking, entrega           |
| `healthcare` | Portal médico               | Historial, citas            |
| `government` | Portal gubernamental        | Documentos, verificación    |

### Métricas de Campaña

| Métrica       | Descripción                       |
|---------------|-----------------------------------|
| `sent`        | Total de mensajes enviados        |
| `delivered`   | Mensajes entregados exitosamente  |
| `opened`      | Mensajes abiertos por el objetivo |
| `clicked`     | Enlaces clickeados                |
| `credentials` | Credenciales capturadas           |
| `report_rate` | Tasa de reporte a seguridad       |

### Configuración

| Parámetro         | Valor por Defecto                 | Descripción              |
|-------------------|-----------------------------------|--------------------------|
| `tracking_server` | `http://localhost:8080`           | Servidor de tracking     |
| `smtp_server`     | Configurado en notifications      | Para envío de emails     |
| `output_dir`      | `~/.blacksentinel-strike/social/`              | Directorio de resultados |
| `campaign_log`    | `~/.blacksentinel-strike/social/campaigns.log` | Registro de campañas     |

---

## 21. Perfiles de Operador

**Propósito**: Gestión de usuarios, roles y permisos con 5 niveles de acceso.

### Qué Hace

El sistema de operadores permite:
- **5 roles**: admin, lead, analyst, viewer, auditor
- **API keys** para acceso programático
- **Gestión de sesiones** con timeout automático
- **Registro de actividad** por operador
- **Permisos granulares** por módulo y acción

### Cómo Usarlo

#### Paso 1: Crear operador (solo admin)

```bash
# Listar operadores existentes
python3 -m modules.operators --list

# Crear nuevo operador
python3 -m modules.operators --create \
    --name "Juan Perez" \
    --email "juan@empresa.com" \
    --role analyst \
    --password "securepassword123"

# Generar API key
python3 -m modules.operators --generate-apikey --user juan
```

#### Paso 2: Autenticarse

```bash
# Login con credenciales
python3 -m modules.operators --login --user juan --password "securepassword123"

# Login con API key
python3 -m modules.operators --login --apikey "pk_abc123..."
```

#### Paso 3: Gestionar sesiones

```bash
# Ver sesiones activas
python3 -m modules.operators --sessions

# Cerrar sesión
python3 -m modules.operators --logout

# Cerrar sesión de otro operador (admin)
python3 -m modules.operators --force-logout --user juan
```

### Roles y Permisos

| Rol       | Permisos              | Descripción                           |
|-----------|-----------------------|---------------------------------------|
| `admin`   | Todos                 | Control total del sistema             |
| `lead`    | Todos excepto admin   | Líder de equipo con acceso completo   |
| `analyst` | Scan, exploit, report | Analista con acceso a herramientas    |
| `viewer`  | Read only, report     | Solo lectura y generación de informes |
| `auditor` | Read only, audit log  | Solo lectura y revisión de logs       |

### Matriz de Permisos

| Acción                | admin | lead | analyst | viewer | auditor |
|-----------------------|-------|------|---------|--------|---------|
| Escaneo de red        | ✅    | ✅   | ✅       | ❌     | ❌      |
| Escáner de puertos    | ✅    | ✅   | ✅       | ❌     | ❌      |
| Explorador web        | ✅    | ✅   | ✅       | ❌     | ❌      |
| Exploits              | ✅    | ✅   | ✅       | ❌     | ❌      |
| War Exploit           | ✅    | ✅   | ✅       | ❌     | ❌      |
| Ataques inalámbricos  | ✅    | ✅   | ✅       | ❌     | ❌      |
| Ingeniería social     | ✅    | ✅   | ❌       | ❌     | ❌      |
| Análisis forense      | ✅    | ✅   | ✅       | ❌     | ❌      |
| Generar informes      | ✅    | ✅   | ✅       | ✅     | ✅      |
| Ver informes          | ✅    | ✅   | ✅       | ✅     | ✅      |
| Configuración         | ✅    | ❌   | ❌       | ❌     | ❌      |
| Gestionar operadores  | ✅    | ❌   | ❌       | ❌     | ❌      |
| Ver logs de auditoría | ✅    | ✅   | ❌       | ❌     | ✅      |
| Gestionar alcance     | ✅    | ✅   | ❌       | ❌     | ❌      |

### Almacenamiento

| Archivo                    | Contenido                     |
|----------------------------|-------------------------------|
| `~/.blacksentinel-strike/operators.enc` | Perfiles de operador cifrados |
| `~/.blacksentinel-strike/api_keys.enc`  | API keys cifradas             |
| `~/.blacksentinel-strike/sessions.json` | Sesiones activas              |

### Configuración

| Parámetro             | Valor por Defecto | Descripción                       |
|-----------------------|-------------------|-----------------------------------|
| `session_timeout`     | 3600              | Timeout de sesión (segundos)      |
| `max_sessions`        | 3                 | Sesiones simultáneas por operador |
| `password_min_length` | 8                 | Longitud mínima de contraseña     |
| `api_key_prefix`      | `pk_`             | Prefijo de API key                |
| `lockout_attempts`    | 5                 | Intentos antes de bloqueo         |

---

## 22. Autorización de Alcance

**Propósito**: Definir y validar objetivos autorizados, exclusiones y límites de prueba.

### Qué Hace

El sistema de alcance permite:
- **Autorización IP**: IPs individuales y rangos
- **CIDR**: Bloques de red completos
- **Wildcard**: Patrones de dominio
- **Dominio**: Dominios específicos
- **Exclusiones**: Objetivos explícitamente excluidos
- **Validación automática**: Verificar objetivos antes de ejecutar

### Cómo Usarlo

#### Paso 1: Definir alcance autorizado

```bash
# Agregar objetivo autorizado
python3 -m modules.scope --add \
    --type ip \
    --value "192.168.1.0/24" \
    --description "Red corporativa principal"

python3 -m modules.scope --add \
    --type domain \
    --value "*.empresa.com" \
    --description "Todos los subdominios de la empresa"

python3 -m modules.scope --add \
    --type cidr \
    --value "10.0.0.0/8" \
    --description "Red interna completa"
```

#### Paso 2: Agregar exclusiones

```bash
# Excluir IPs específicas
python3 -m modules.scope --exclude \
    --type ip \
    --value "192.168.1.1" \
    --description "Gateway - no probar"

python3 -m modules.scope --exclude \
    --type ip \
    --value "192.168.1.10" \
    --description "Servidor de producción crítico"

# Excluir rangos
python3 -m modules.scope --exclude \
    --type cidr \
    --value "192.168.1.240/28" \
    --description "Segmento de红 critical infrastructure"
```

#### Paso 3: Validar objetivo

```bash
# Verificar si un objetivo está en alcance
python3 -m modules.scope --validate --target "192.168.1.50"
# Salida: ✅ OBJETIVO AUTORIZADO

python3 -m modules.scope --validate --target "192.168.1.1"
# Salida: ❌ OBJETIVO EXCLUIDO - Gateway - no probar

python3 -m modules.scope --validate --target "10.0.0.1"
# Salida: ✅ OBJETIVO AUTORIZADO

python3 -m modules.scope --validate --target "8.8.8.8"
# Salida: ❌ FUERA DE ALCANCE
```

#### Paso 4: Gestionar alcance

```bash
# Listar alcance completo
python3 -m modules.scope --list

# Exportar alcance
python3 -m modules.scope --export --output scope.json

# Importar alcance
python3 -m modules.scope --import --file scope.json

# Limpiar todo el alcance
python3 -m modules.scope --clear --confirm
```

### Tipos de Alcance

| Tipo       | Formato            | Ejemplo                     |
|------------|--------------------|-----------------------------|
| `ip`       |  IP individual     | `192.168.1.50`              |
| `cidr`     | Bloque CIDR        | `192.168.1.0/24`            |
| `wildcard` | Dominio comodín    | `*.empresa.com`             |
| `domain`   | Dominio específico | `web.empresa.com`           |
| `range`    | Rango de IPs       | `192.168.1.1-192.168.1.254` |

### Almacenamiento

| Archivo                           | Contenido                  |
|-----------------------------------|----------------------------|
| `~/.blacksentinel-strike/scope.enc`            | Alcance autorizado cifrado |
| `~/.blacksentinel-strike/scope_exclusions.enc` | Exclusiones cifradas       |

### Configuración

| Parámetro          | Valor por Defecto | Descripción                              |
|--------------------|-------------------|------------------------------------------|
| `enforce_scope`    | `true`            | Bloquear objetivos fuera de alcance      |
| `warn_on_exclude`  | `true`            | Advertir al intentar probar exclusiones  |
| `log_validations`  | `true`            | Registrar todas las validaciones         |
| `require_approval` | `false`           | Requerir aprobación para nuevos alcances |

---

## 23. Registro de Auditoría

**Propósito**: Logging persistente con rotación, pista de auditoría inmutable y registro de actividad del sistema.

### Qué Hace

El sistema de auditoría proporciona:
- **JSON estructurado**: Cada evento es un objeto JSON completo
- **Rotación automática**: Archivos de 10MB, 10 rotaciones máximo
- **Pista de auditoría**: Hash de integridad encadenado (cada línea depende de la anterior)
- **Registro de actividad**: Login, escaneos, exploits, configuración, errores
- **Filtrado**: Por operador, acción, fecha, severidad

### Cómo Usarlo

#### Paso 1: Ver logs de auditoría

```bash
# Listar archivos de log
ls ~/.blacksentinel-strike/logs/

# Ver último log
python3 -m modules.audit_log --tail 50

# Filtrar por operador
python3 -m modules.audit_log --filter --operator juan

# Filtrar por acción
python3 -m modules.audit_log --filter --action "scan_started"

# Filtrar por rango de fechas
python3 -m modules.audit_log --filter --from "2024-01-01" --to "2024-12-31"
```

#### Paso 2: Verificar integridad

```bash
# Verificar hash de integridad
python3 -m modules.audit_log --verify

# Salida esperada:
# ✅ Línea 1: Hash verificado
# ✅ Línea 2: Hash verificado
# ...
# ✅ 150 entradas verificadas - Integridad confirmada
```

#### Paso 3: Exportar logs

```bash
# Exportar a CSV
python3 -m modules.audit_log --export --format csv --output audit_export.csv

# Exportar a JSON
python3 -m modules.audit_log --export --format json --output audit_export.json

# Exportar filtrado
python3 -m modules.audit_log --export --filter --action "exploit_run" --output exploits.csv
```

### Estructura de Eventos

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "operator": "juan",
  "action": "scan_started",
  "module": "recon",
  "target": "192.168.1.0/24",
  "parameters": {
    "scan_type": "syn",
    "timeout": 300
  },
  "result": "success",
  "severity": "info",
  "hash": "sha256:abc123...",
  "prev_hash": "sha256:def456..."
}
```

### Tipos de Eventos

| Evento             | Descripción              | Severidad |
|--------------------|--------------------------|-----------|
| `login_success`    | Login exitoso            | info      |
| `login_failed`     | Login fallido            | warning   |
| `scan_started`     | Escaneo iniciado         | info      |
| `scan_completed`   | Escaneo completado       | info      |
| `exploit_run`      | Exploit ejecutado        | warning   |
| `exploit_success`  | Vulnerabilidad explotada | critical  |
| `config_changed`   | Configuración modificada | warning   |
| `scope_violation`  | Intento fuera de alcance | critical  |
| `operator_created` | Operador creado          | info      |
| `operator_deleted` | Operador eliminado       | warning   |

### Rotación de Logs

| Parámetro         | Valor                        | Descripción                       |
|-------------------|------------------------------|-----------------------------------|
| Tamaño máximo     | 10 MB                        | Cada archivo de log               |
| Archivos rotados  | 10                           | Máximo de archivos históricos     |
| Nombre de archivo | `audit_YYYYMMDD_HHMMSS.json` | Formato timestamp                 |
| Compresión        | gzip                         | Al rotar, se comprime el anterior |

### Almacenamiento

| Archivo                           | Contenido                     |
|-----------------------------------|-------------------------------|
| `~/.blacksentinel-strike/logs/audit_*.json`    | Logs de auditoría actuales    |
| `~/.blacksentinel-strike/logs/audit_*.json.gz` | Logs de auditoría comprimidos |

### Configuración

| Parámetro         | Valor por Defecto | Descripción                      |
|-------------------|-------------------|----------------------------------|
| `enabled`         | `true`            | Habilitar logging de auditoría   |
| `max_file_size`   | 10485760          | Tamaño máximo por archivo (10MB) |
| `max_rotations`   | 10                | Número máximo de rotaciones      |
| `integrity_check` | `true`            | Verificar integridad al leer     |
| `log_level`       | `info`            | Nivel mínimo de logging          |

---

## 24. Notificaciones

**Propósito**: Sistema de alertas por email (SMTP) y webhooks (Slack, Discord, Microsoft Teams).

### Qué Hace

El sistema de notificaciones permite:
- **Email SMTP**: Alertas por correo electrónico con adjuntos
- **Webhooks**: Notificaciones a Slack, Discord, Microsoft Teams
- **Filtrado por severidad**: Solo recibir alertas críticas o superiores
- **Plantillas personalizadas**: Mensajes formateados por tipo de evento
- **Rate limiting**: Evitar inundación de notificaciones

### Cómo Usarlo

#### Paso 1: Configurar notificaciones por email

```bash
# Configurar servidor SMTP
python3 -m modules.notifications --config smtp \
    --host smtp.empresa.com \
    --port 587 \
    --user alerts@empresa.com \
    --password "password" \
    --tls

# Agregar destinatarios
python3 -m modules.notifications --add-email \
    --recipient "admin@empresa.com" \
    --severity critical

python3 -m modules.notifications --add-email \
    --recipient "team@empresa.com" \
    --severity warning
```

#### Paso 2: Configurar webhooks

```bash
# Slack
python3 -m modules.notifications --config webhook \
    --type slack \
    --url "https://hooks.slack.com/services/T00/B00/xxx" \
    --severity critical

# Discord
python3 -m modules.notifications --config webhook \
    --type discord \
    --url "https://discord.com/api/webhooks/xxx" \
    --severity warning

# Microsoft Teams
python3 -m modules.notifications --config webhook \
    --type teams \
    --url "https://outlook.office.com/webhook/xxx" \
    --severity critical
```

#### Paso 3: Probar notificaciones

```bash
# Enviar prueba
python3 -m modules.notifications --test --channel email
python3 -m modules.notifications --test --channel slack

# Ver configuración actual
python3 -m modules.notifications --status
```

### Eventos Notificables

| Evento                             | Severidad | Email | Webhook |
|------------------------------------|-----------|-------|---------|
| Vulnerabilidad crítica descubierta | critical  | ✅    | ✅      |
| Exploit ejecutado exitosamente     | high      | ✅    | ✅      |
| Login fallido múltiple             | warning   | ✅    | ✅      |
| Violación de alcance               | critical  | ✅    | ✅      |
| Escaneo completado                 | info      | ❌    | ❌      |
| Operador bloqueado                 | warning   | ✅    | ✅      |
| Error del sistema                  | error     | ✅    | ✅      |

### Plantillas de Mensaje

```json
{
  "subject": "[BlackSentinel] ALERTA: Vulnerabilidad crítica detectada",
  "body": "Se ha detectado una vulnerabilidad crítica en el objetivo {target}.\n\nDetalles:\n- CVE: {cve}\n- Severidad: {severity}\n- Operador: {operator}\n- Timestamp: {timestamp}\n\nAcción requerida.",
  "fields": {
    "target": "IP del objetivo",
    "cve": "Identificador CVE",
    "severity": "Nivel de severidad",
    "operator": "Operador que ejecutó"
  }
}
```

### Configuración

| Parámetro        | Valor por Defecto           | Descripción                     |
|------------------|-----------------------------|---------------------------------|
| `enabled`        | `true`                      | Habilitar notificaciones        |
| `min_severity`   | `warning`                   | Severidad mínima para notificar |
| `rate_limit`     | 10                          | Max notificaciones por hora     |
| `batch_interval` | 300                         | Segundos entre envíos agrupados |
| `retry_attempts` | 3                           | Intentos de reenvío             |
| `output_dir`     | `~/.blacksentinel-strike/notifications/` | Directorio de logs              |

---

## 25. Limitación de Velocidad y Sigilo

**Propósito**: Throttling inteligente con ventana deslizante y modos de sigilo configurables.

### Qué Hace

Este módulo combina dos sistemas:
- **Limitación de Velocidad**: Controla la tasa de peticiones para evitar detección
- **Modos de Sigilo**: 4 niveles de sigilo con comportamientos diferentes

### Limitación de Velocidad

#### Cómo Usarlo

```bash
# Configurar límites por objetivo
python3 -m modules.throttle --config \
    --max-requests 100 \
    --window 60 \
    --per-target 192.168.1.0/24

# Ver estado de rate limiting
python3 -m modules.throttle --status

# Resetear contadores
python3 -m modules.throttle --reset --target 192.168.1.50
```

#### Algoritmo de Ventana Deslizante

```
Tiempo:    |----60 segundos----|
Peticiones: [███░░░░░░░░░░░░███] → 3 peticiones en ventana
Límite:     100 requests por 60 segundos

Si se excede: RateLimitException → Esperar hasta ventana siguiente
```

#### Configuración de Throttling

| Parámetro        | Valor por Defecto | Descripción                         |
|------------------|-------------------|-------------------------------------|
| `max_requests`   | 100               | Máximo de peticiones por ventana    |
| `window_seconds` | 60                | Duración de la ventana (segundos)   |
| `per_target`     | `true`            | Límites independientes por objetivo |
| `global_limit`   | 1000              | Límite global del sistema           |
| `burst_allowed`  | `false`           | Permitir ráfagas iniciales          |

### Modos de Sigilo

#### Paso 1: Seleccionar modo de sigilo

```bash
# Configurar modo de sigilo
python3 -m modules.stealth --set-mode quiet

# Verificar modo actual
python3 -m modules.stealth --status
```

#### Los 4 Modos

| Modo         | Descripción                      | Velocidad | Detección |
|--------------|----------------------------------|-----------|-----------|
| `passive`    | Solo escucha, no envía paquetes  | Muy lenta | Mínima    |
| `quiet`      | Escaneo mínimo, paquetes lentos  | Lenta     | Baja      |
| `moderate`   | Balance entre velocidad y sigilo | Media     | Media     |
| `aggressive` | Velocidad máxima, mínimo sigilo  | Rápida    | Alta      |

#### Detalle por Modo

##### Passive (Pasivo)
```bash
python3 -m modules.stealth --set-mode passive
```
- Solo captura tráfico existente (sniffing)
- No genera tráfico nuevo
- Ideal para reconocimiento inicial
- No detecta servicios que no estén activos

##### Quiet (Sigiloso)
```bash
python3 -m modules.stealth --set-mode quiet
```
- Escaneo con paquetes lentos (1 paquete/segundo)
- Randomización de intervalos (jitter ±50%)
- TTL randomizado
- Fragmentación de paquetes
- Ideal para evadir IDS básico

##### Moderate (Moderado)
```bash
python3 -m modules.stealth --set-mode moderate
```
- Balance entre velocidad y detección
- Jitter ±25%
- Paquetes légèrement fragmentados
- Ideal para la mayoría de evaluaciones

##### Aggressive (Agresivo)
```bash
python3 -m modules.stealth --set-mode aggressive
```
- Velocidad máxima de escaneo
- Sin jitter ni fragmentación
- Ideal para redes internas autorizadas

#### Características por Modo

| Característica    | passive     | quiet | moderate | aggressive |
|-------------------|-------------|-------|----------|------------|
| Paquetes/segundo  | 0           | 1     | 10       | 100+       |
| Jitter            | N/A         | ±50%  | ±25%     | 0%         |
| TTL randomizado   | ❌          | ✅     | ✅       | ❌         |
| Fragmentación     | ❌          | ✅     | Parcial  | ❌         |
| Decoys            | ❌          | ❌     | ✅       | ✅         |
| Detección por IDS | Inexistente | Baja  | Media    | Alta       |

#### Uso de Decoys

```bash
# Habilitar decoys en modo moderate/aggressive
python3 -m modules.stealth --set-mode moderate --decoys 5

# Los decoys son IPs falsas que mezclan con el tráfico real
# Makes it harder to identify the real attacker IP
```

### Configuración

| Parámetro       | Valor por Defecto | Descripción                  |
|-----------------|-------------------|------------------------------|
| `default_mode`  | `moderate`        | Modo de sigilo por defecto   |
| `jitter_range`  | 0.25              | Rango de jitter (0-1)        |
| `decoy_count`   | 0                 | Número de decoys             |
| `fragment_size` | 8                 | Tamaño de fragmentos (bytes) |
| `ttl_min`       | 32                | TTL mínimo randomizado       |
| `ttl_max`       | 128               | TTL máximo randomizado       |

---

## 26. Base de Datos e Historial

**Propósito**: Almacenamiento SQLite persistente con cifrado, historial de hallazgos, estadísticas y exportación.

### Qué Hace

El módulo de base de datos proporciona:
- **SQLite cifrado**: Base de datos en reposo con cifrado automático
- **Historial de hallazgos**: Registro completo de todos los descubrimientos
- **Estadísticas**: Métricas de actividad y rendimiento
- **Exportación**: Múltiples formatos (JSON, CSV, PDF)
- **Backup automático**: Respaldos programados de la base de datos

### Cómo Usarlo

#### Paso 1: Consultar historial

```bash
# Ver todos los hallazgos
python3 -m modules.database --list

# Filtrar por tipo
python3 -m modules.database --list --type vulnerability

# Filtrar por severidad
python3 -m modules.database --list --severity critical

# Filtrar por fecha
python3 -m modules.database --list --from "2024-01-01" --to "2024-01-31"

# Buscar por objetivo
python3 -m modules.database --search --target 192.168.1.50
```

#### Paso 2: Ver estadísticas

```bash
# Estadísticas generales
python3 -m modules.database --stats

# Salida:
# Total de hallazgos: 1,247
# Por severidad:
#   - Critical: 23
#   - High: 156
#   - Medium: 534
#   - Low: 534
# Por módulo:
#   - War Exploit: 45
#   - Network: 234
#   - Web: 567
#   - Wireless: 123
# Por operador:
#   - juan: 456
#   - maria: 791

# Estísticas por período
python3 -m modules.database --stats --period 30d
```

#### Paso 3: Exportar datos

```bash
# Exportar a JSON
python3 -m modules.database --export --format json --output findings.json

# Exportar a CSV
python3 -m modules.database --export --format csv --output findings.csv

# Exportar filtrado
python3 -m modules.database --export \
    --format json \
    --filter "severity=critical AND module=war_exploit" \
    --output critical_findings.json
```

### Tablas de la Base de Datos

#### tabla `findings`

| Campo         | Tipo    | Descripción                               |
|---------------|---------|-------------------------------------------|
| `id`          | INTEGER | ID único del hallazgo                     |
| `timestamp`   | TEXT    | Fecha/hora ISO 8601                       |
| `operator`    | TEXT    | Operador que encontró el hallazgo         |
| `target`      | TEXT    | IP/hostname del objetivo                  |
| `module`      | TEXT    | Módulo que encontró                       |
| `type`        | TEXT    | Tipo de hallazgo                          |
| `severity`    | TEXT    | Severidad (critical/high/medium/low/info) |
| `title`       | TEXT    | Título del hallazgo                       |
| `description` | TEXT    | Descripción detallada                     |
| `evidence`    | TEXT    | Evidencia (hashes, capturas)              |
| `cve`         | TEXT    | Identificador CVE (si aplica)             |
| `remediation` | TEXT    | Recomendación de remediación              |

#### tabla `scans`

| Campo            | Tipo    | Descripción                       |
|------------------|---------|-----------------------------------|
| `id`             | INTEGER | ID único del escaneo              |
| `timestamp`      | TEXT    | Fecha/hora de inicio              |
| `operator`       | TEXT    | Operador que ejecutó              |
| `module`         | TEXT    | Módulo utilizado                  |
| `target`         | TEXT    | Objetivo del escaneo              |
| `status`         | TEXT    | Estado (running/completed/failed) |
| `duration`       | TEXT    | Duración total                    |
| `findings_count` | INTEGER | Número de hallazgos               |

#### tabla `sessions`

| Campo         | Tipo    | Descripción                 |
|---------------|---------|-----------------------------|
| `id`          | INTEGER | ID de la sesión             |
| `operator`    | TEXT    | Operador                    |
| `login_time`  | TEXT    | Hora de login               |
| `logout_time` | TEXT    | Hora de logout              |
| `ip_address`  | TEXT    | IP del cliente              |
| `actions`     | TEXT    | JSON de acciones realizadas |

### Almacenamiento

| Archivo                              | Contenido               |
|--------------------------------------|-------------------------|
| `~/.blacksentinel-strike/database/blacksentinel.db`     | Base de datos principal |
| `~/.blacksentinel-strike/database/blacksentinel.db-wal` | Write-Ahead Log         |
| `~/.blacksentinel-strike/database/blacksentinel.db-shm` | Shared Memory           |
| `~/.blacksentinel-strike/database/backups/`       | Respaldos automáticos   |

### Configuración

| Parámetro         | Valor por Defecto                | Descripción                |
|-------------------|----------------------------------|----------------------------|
| `db_path`         | `~/.blacksentinel-strike/database/blacksentinel.db` | Ruta de la base de datos   |
| `backup_interval` | 86400                            | Segundos entre respaldos   |
| `max_backups`     | 7                                | Máximo de respaldos        |
| `auto_cleanup`    | `true`                           | Limpiar registros antiguos |
| `retention_days`  | 365                              | Días de retención          |

---

## 27. CI/CD y Despliegue

**Propósito**: Integración continua con GitHub Actions, despliegue con Docker Compose y automatización con Makefile.

### Qué Hace

El sistema de CI/CD proporciona:
- **GitHub Actions**: 3 pipelines automáticos (CI, release, schedule)
- **Docker Compose**: Orquestación multi-servicio
- **Makefile**: Comandos de desarrollo y despliegue

### GitHub Actions

#### Pipeline CI (`ci.yml`)

Se ejecuta automáticamente en cada push y PR:

```yaml
# .github/workflows/ci.yml
name: CI Pipeline
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: make install
      - name: Run tests
        run: make test
      - name: Run linting
        run: make lint
```

#### Pipeline Release (`release.yml`)

Se ejecuta al crear un tag de versión:

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags: ['v*']
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build Docker image
        run: docker build -t blacksentinel-strike:${{ github.ref_name }} .
      - name: Push to registry
        run: docker push blacksentinel-strike:${{ github.ref_name }}
```

#### Pipeline Schedule (`schedule.yml`)

Ejecución programada (diaria/semanal):

```yaml
# .github/workflows/schedule.yml
name: Scheduled Security Scan
on:
  schedule:
    - cron: '0 2 * * 1'  # Cada lunes a las 2am
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Run security audit
        run: make security-audit
      - name: Update dependencies
        run: make update-deps
```

### Docker Compose

#### Configuración (`docker-compose.yml`)

```yaml
version: '3.8'
services:
  blacksentinel-gui:
    build: .
    ports:
      - "5900:5900"    # VNC
      - "8080:8080"    # Web UI
    volumes:
      - blacksentinel-data:/root/.blacksentinel-strike
    environment:
      - BLACKSENTINEL_MODE=server
    networks:
      - blacksentinel-net

  blacksentinel-db:
    image: sqlite:latest
    volumes:
      - blacksentinel-db:/data
    networks:
      - blacksentinel-net

  blacksentinel-web:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    networks:
      - blacksentinel-net

volumes:
  blacksentinel-data:
  blacksentinel-db:

networks:
  blacksentinel-net:
    driver: bridge
```

#### Comandos Docker Compose

```bash
# Iniciar todos los servicios
docker-compose up -d

# Ver estado
docker-compose ps

# Ver logs
docker-compose logs -f blacksentinel-gui

# Detener todos
docker-compose down

# Reconstruir
docker-compose build --no-cache
```

### Makefile

#### Comandos Disponibles

| Comando                 | Descripción                          |
|-------------------------|--------------------------------------|
| `make install`          | Instalación completa del sistema     |
| `make deploy`           | Despliegue con Docker + verificación |
| `make test`             | Ejecutar suite de pruebas            |
| `make test-unit`        | Solo pruebas unitarias               |
| `make test-integration` | Solo pruebas de integración          |
| `make lint`             | Verificar estilo de código           |
| `make format`           | Formatear código                     |
| `make security-audit`   | Auditoría de seguridad               |
| `make update-deps`      | Actualizar dependencias              |
| `make clean`            | Limpiar archivos temporales          |
| `make backup`           | Crear respaldo de configuración      |
| `make restore`          | Restaurar desde respaldo             |

#### Ejemplo de Uso del Makefile

```bash
# Instalación completa
make install

# Ejecutar pruebas después de cambios
make test

# Desplegar en servidor
make deploy

# Crear respaldo antes de actualizar
make backup
make update-deps
make test
```

### Configuración de Despliegue

| Parámetro         | Valor por Defecto | Descripción              |
|-------------------|-------------------|--------------------------|
| `docker_registry` | `ghcr.io`         | Registro de contenedores |
| `image_name`      | `blacksentinel-strike` | Nombre de la imagen      |
| `container_port`  | 8080              | Puerto de la GUI web     |
| `vnc_port`        | 5900              | Puerto VNC               |
| `data_volume`     | `blacksentinel-data`    | Volumen de datos         |

---

## 28. Pruebas

**Propósito**: Suite completa de pruebas con 139 tests pytest y comandos de automatización.

### Qué Hace

El sistema de pruebas incluye:
- **139 tests** automatizados
- **Pruebas unitarias**: Cada módulo tiene sus propias pruebas
- **Pruebas de integración**: Flujos completos de usuario
- **Cobertura de código**: Reporte automático de cobertura
- **Mocking**: Simulación de herramientas externas

### Cómo Usarlo

#### Ejecutar todas las pruebas

```bash
make test
# o directamente:
pytest tests/ -v
```

#### Ejecutar por categoría

```bash
# Pruebas unitarias
make test-unit
# o:
pytest tests/unit/ -v

# Pruebas de integración
make test-integration
# o:
pytest tests/integration/ -v

# Pruebas de un módulo específico
pytest tests/unit/test_vault.py -v
pytest tests/unit/test_database.py -v
pytest tests/unit/test_audit_log.py -v
```

#### Generar reporte de cobertura

```bash
pytest tests/ --cov=modules --cov-report=html --cov-report=term
```

### Estructura de Pruebas

```
tests/
├── conftest.py           # Fixtures compartidos
├── unit/
│   ├── test_vault.py     # Pruebas de cifrado
│   ├── test_database.py  # Pruebas de base de datos
│   ├── test_audit_log.py # Pruebas de auditoría
│   ├── test_operators.py # Pruebas de operadores
│   ├── test_scope.py     # Pruebas de alcance
│   ├── test_notifications.py # Pruebas de notificaciones
│   ├── test_throttle.py  # Pruebas de rate limiting
│   ├── test_stealth.py   # Pruebas de sigilo
│   ├── test_recon.py     # Pruebas de reconocimiento
│   ├── test_web.py       # Pruebas web
│   ├── test_exploits.py  # Pruebas de exploits
│   ├── test_wireless.py  # Pruebas inalámbricas
│   ├── test_network.py   # Pruebas de red
│   ├── test_social.py    # Pruebas de ingeniería social
│   ├── test_forensic.py  # Pruebas forenses
│   └── test_reports.py   # Pruebas de informes
├── integration/
│   ├── test_full_scan.py     # Flujo completo de escaneo
│   ├── test_war_exploit.py   # Pipeline War Exploit
│   └── test_end_to_end.py    # Prueba de extremo a extremo
└── fixtures/
    ├── sample_scan.json      # Datos de escaneo de ejemplo
    ├── sample_findings.json  # Hallazgos de ejemplo
    └── test_config.json      # Configuración de prueba
```

### Tipos de Pruebas

| Tipo        | Cantidad | Descripción                       |
|-------------|----------|-----------------------------------|
| Unitarias   | 95       | Pruebas aisladas de cada módulo   |
| Integración | 30       | Flujos combinados de módulos      |
| Funcionales | 14       | Pruebas de funcionalidad completa |
| **Total**   | **139**  | Cobertura completa del sistema    |

### Ejemplos de Pruebas

#### Prueba de Cifrado (vault)

```python
def test_encrypt_decrypt():
    vault = VaultMaster("test_password")
    data = " Datos sensibles"
    encrypted = vault.encrypt(data)
    decrypted = vault.decrypt(encrypted)
    assert decrypted == data

def test_wrong_password_fails():
    vault = VaultMaster("correct_password")
    encrypted = vault.encrypt("secret")
    vault2 = VaultMaster("wrong_password")
    with pytest.raises(DecryptionError):
        vault2.decrypt(encrypted)
```

#### Prueba de Base de Datos

```python
def test_add_finding():
    db = BlackSentinelDB(":memory:")
    finding = db.add_finding(
        target="192.168.1.50",
        severity="high",
        title="SQL Injection",
        description="Found in login form"
    )
    assert finding.id is not None
    assert db.get_finding(finding.id).severity == "high"

def test_stats():
    db = BlackSentinelDB(":memory:")
    db.add_finding(severity="critical", ...)
    db.add_finding(severity="high", ...)
    stats = db.get_stats()
    assert stats["critical"] == 1
    assert stats["high"] == 1
```

### Configurar Cobertura

```bash
# Configuración en pytest.ini o pyproject.toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "--cov=modules --cov-report=term-missing"

# Ejecutar con cobertura
pytest --cov=modules --cov-report=html
# Abrir htmlcov/index.html en el navegador
```

### Comandos Útiles de Pytest

| Comando                  | Descripción                        |
|--------------------------|------------------------------------|
| `pytest -v`              | Salida detallada                   |
| `pytest -x`              | Detener en primer error            |
| `pytest -k "test_vault"` | Ejecutar pruebas que coincidan     |
| `pytest --lf`            | Re-ejecutar pruebas fallidas       |
| `pytest --co`            | Solo mostrar pruebas (no ejecutar) |
| `pytest -m "not slow"`   | Excluir pruebas lentas             |

---

## 29. Listas de Palabras

**Propósito**: Listas de palabras preinstaladas para ataques de fuerza bruta y fuzzing.

### Ubicación

Todas las listas de palabras se encuentran en:

```
~/.blacksentinel-strike/wordlists/
├── rockyou.txt           # 14M contraseñas - Propósito general
├── commonPasswords.txt   # 10K contraseñas comunes
├── top-20.txt            # 20 contraseñas más usadas
├── web.txt               # 50K palabras para fuzzing web
├── usernames.txt         # 10K nombres de usuario comunes
└── custom.txt            # Lista personalizada del usuario
```

### Listas Disponibles

| Lista                 | Tamaño   | Líneas   | Uso Recomendado         |
|-----------------------|----------|----------|-------------------------|
| `rockyou.txt`         | 139 MB   | 14.3M    | Fuerza bruta general    |
| `commonPasswords.txt` | 89 KB    | 10,000   | Prueba rápida           |
| `top-20.txt`          | 352 B    | 20       | Verificación básica     |
| `web.txt`             | 412 KB   | 50,000   | Fuzzing de directorios  |
| `usernames.txt`       | 156 KB   | 10,000   | Enumeración de usuarios |
| `custom.txt`          | Variable | Variable | Ataques dirigidos       |

### Cómo Usarlas

#### En ataques de contraseñas (Hydra)

```bash
# Usar rockyou.txt para fuerza bruta completa
python3 -m modules.bruteforce \
    --target 192.168.1.50 \
    --protocol ssh \
    --user admin \
    --wordlist ~/.blacksentinel-strike/wordlists/rockyou.txt

# Usar commonPasswords.txt para prueba rápida
python3 -m modules.bruteforce \
    --target 192.168.1.50 \
    --protocol ssh \
    --user admin \
    --wordlist ~/.blacksentinel-strike/wordlists/commonPasswords.txt

# Usar top-20.txt para verificación básica
python3 -m modules.bruteforce \
    --target 192.168.1.50 \
    --protocol ssh \
    --user admin \
    --wordlist ~/.blacksentinel-strike/wordlists/top-20.txt
```

#### En fuzzing web (Gobuster/FFuf)

```bash
# Usar web.txt para descubrimiento de directorios
gobuster dir -u http://192.168.1.50 \
    -w ~/.blacksentinel-strike/wordlists/web.txt \
    -t 10

# Usar common.txt (sistema) para listados rápidos
ffuf -u http://192.168.1.50/FUZZ \
    -w /usr/share/wordlists/dirb/common.txt \
    -mc 200,301,302,403
```

#### Crear lista personalizada

```bash
# Agregar palabras a la lista personalizada
echo "nuevapalabra" >> ~/.blacksentinel-strike/wordlists/custom.txt

# O crear desde cero
cat > ~/.blacksentinel-strike/wordlists/custom.txt << EOF
password123
empresa2024
admin123
EOF
```

### Configuración

| Parámetro          | Valor por Defecto                 | Descripción                                |
|--------------------|-----------------------------------|--------------------------------------------|
| `default_wordlist` | `rockyou.txt`                     | Lista por defecto para fuerza bruta        |
| `default_weblist`  | `web.txt`                         | Lista por defecto para fuzzing web         |
| `custom_path`      | `~/.blacksentinel-strike/wordlists/custom.txt` | Ruta de lista personalizada                |
| `auto_download`    | `true`                            | Descargar listas faltantes automáticamente |

### Descargar Listas Adicionales

```bash
# Descargar SecLists completo
cd ~/.blacksentinel-strike/wordlists/
curl -sL https://github.com/danielmiessler/SecLists/archive/master.zip -o seclists.zip
unzip seclists.zip
rm seclists.zip

# Descargar listas específicas
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt -o 10k-common.txt
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -o web-common.txt
```

---

*BlackSentinel Pentest Suite v4.0.*
