# BlackSentinel Strike - Deployment Guide

## Quick Deployment Options

### Option 1: Direct Installation (Recommended for Individual Use)

```bash
# Clone or copy the project
cd ~/tools
git clone <repository> blacksentinel-strike
cd blacksentinel-strike/pentest-gui

# Run automated deployment
bash deploy.sh

# Launch
python3 app.py
```

### Option 2: Docker Deployment (Recommended for Organizations)

```bash
cd pentest-gui

# Build and run
docker build -t blacksentinel-strike:latest .
docker run -it --net=host blacksentinel-strike:latest

# Or use docker-compose
docker-compose up -d
```

### Option 3: Production Deployment (Multi-User)

```bash
# Kali Linux
sudo bash deploy_kali.sh

# macOS
bash deploy_production.sh --macos

# Docker production
bash deploy_docker_production.sh
```

---

## Organization Deployment

### For Security Teams (5-50 users)

1. **Central Server Installation**
```bash
# Install on dedicated server
sudo bash deploy_kali.sh

# Create operator accounts
python3 -c "
from modules.operators import create_operator
create_operator('analyst1', 'secure_pass', 'analyst', 'Security Analyst')
create_operator('analyst2', 'secure_pass', 'analyst', 'Security Analyst')
"
```

2. **Client Access**
- Web-based access via noVNC (port 6080)
- Direct VNC access (port 5900)
- Docker container isolation

3. **Shared Vault Configuration**
```bash
# Configure shared vault
export VAULT_DIR=/shared/blacksentinel/vault
export BLACKSENTINEL_MODE=production
```

### For Enterprise (50+ users)

1. **Kubernetes Deployment**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blacksentinel-strike
spec:
  replicas: 3
  selector:
    matchLabels:
      app: blacksentinel-strike
  template:
    metadata:
      labels:
        app: blacksentinel-strike
    spec:
      containers:
      - name: blacksentinel
        image: blacksentinel-strike:latest
        ports:
        - containerPort: 5900
        - containerPort: 6080
```

2. **Load Balancer Configuration**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: blacksentinel-service
spec:
  type: LoadBalancer
  ports:
  - port: 5900
    targetPort: 5900
  - port: 6080
    targetPort: 6080
  selector:
    app: blacksentinel-strike
```

---

## Distribution Methods

### Method 1: GitHub Repository (Public/Private)

```bash
# Initialize git repository
cd pentest-gui
git init
git add .
git commit -m "BlackSentinel Strike v4.0 - Initial Release"

# Add remote
git remote add origin https://github.com/your-org/blacksentinel-strike.git
git push -u origin main
```

### Method 2: Private Git Server

```bash
# Create bare repository
git init --bare /srv/git/blacksentinel-strike.git

# Push from development
git remote add release /srv/git/blacksentinel-strike.git
git push release main
```

### Method 3: Package Distribution

```bash
# Create distributable package
bash package_build.sh

# Output: blacksentinel-strike-v4.0.tar.gz
```

### Method 4: Docker Registry

```bash
# Build and tag
docker build -t your-registry.com/blacksentinel-strike:v4.0 .
docker push your-registry.com/blacksentinel-strike:v4.0

# Users pull and run
docker pull your-registry.com/blacksentinel-strike:v4.0
docker run -it your-registry.com/blacksentinel-strike:v4.0
```

### Method 5: USB/Portable Distribution

```bash
# Create portable package
bash package_build.sh --portable

# Output includes:
# - blacksentinel-strike-v4.0/
# - install.sh (auto-installer)
# - README.md
# - requirements.txt
```

---

## Licensing Options

### Option A: Proprietary License (Default)
- All rights reserved by BlackSentinel Strike
- Requires explicit authorization for use
- Suitable for: Internal security teams, consultants

### Option B: Enterprise License
- Per-user or per-organization licensing
- Includes support and updates
- Suitable for: Large organizations, MSSPs

### Option C: Open Source (Limited)
- Core functionality open source
- Advanced features proprietary
- Suitable for: Community adoption, education

### Option D: Custom License
- Tailored to organization needs
- Custom features and support
- Suitable for: Government, critical infrastructure

---

## Pricing Models (If Commercial)

### Individual License
- 1 user, 1 year
- Includes: All features, email support
- Price: $99/year

### Team License
- Up to 10 users, 1 year
- Includes: All features, priority support, updates
- Price: $799/year

### Enterprise License
- Unlimited users, 1 year
- Includes: All features, 24/7 support, custom development
- Price: $4,999/year

### MSSP License
- Managed security service provider
- White-label option available
- Includes: Multi-tenant support, API access
- Price: Custom

---

## Compliance and Certification

### Supported Standards
- OWASP Testing Guide v4.2
- NIST SP 800-115
- PTES (Penetration Testing Execution Standard)
- OSSTMM (Open Source Security Testing Methodology Manual)

### Audit Trail
- All actions logged with timestamps
- Encrypted audit logs in vault
- Exportable compliance reports

### Data Protection
- AES-256-CBC encryption at rest
- TLS 1.3 for network communications
- GDPR-compliant data handling

---

## Support Channels

### Community Support
- GitHub Issues: https://github.com/blacksentinel-strike/blacksentinel-strike/issues
- Documentation: See MANUAL.md and MANUAL_ES.md

### Professional Support
- Email: support@blacksentinel-strike.com
- Response time: 24-48 hours

### Enterprise Support
- Dedicated support team
- Custom development available
- On-site training available

---

## Update Strategy

### Automatic Updates
```bash
# Enable auto-updates in Settings
# Updates checked from configured URL
```

### Manual Updates
```bash
# Download latest version
git pull origin main

# Or download release package
bash deploy.sh --update
```

### Version Management
- Current version: 4.0.0
- Semantic versioning: MAJOR.MINOR.PATCH
- Changelog maintained in CHANGELOG.md

---

## Backup and Recovery

### Automated Backups
```bash
# Create backup
python3 -c "
from modules.updater import backup_current
path = backup_current()
print(f'Backup created: {path}')
"
```

### Manual Backup
```bash
# Backup vault
cp -r ~/.blacksentinel-strike/vault/ /secure/backup/

# Backup configuration
cp ~/.blacksentinel-strike/vault/config.enc /secure/backup/
```

### Recovery
```bash
# Restore from backup
cp -r /secure/backup/vault/ ~/.blacksentinel-strike/
```

---

## Security Hardening

### Server Hardening
```bash
# Firewall rules
ufw allow 5900/tcp  # VNC
ufw allow 6080/tcp  # noVNC
ufw deny 5900/udp
ufw deny 6080/udp

# Enable fail2ban
apt install fail2ban
systemctl enable fail2ban
```

### Application Hardening
- Run with minimal privileges
- Use strong master passwords
- Enable IP rotation
- Use VPN for remote access
- Regular security audits

---

## Contact

**BlackSentinel Strike**
Cybersecurity and Autonomous Defense

For deployment assistance:
- Email: deploy@blacksentinel-strike.com
- Documentation: See README.md
