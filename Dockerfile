FROM kalilinux/kali-rolling

LABEL maintainer="BlackSentinel Strike"
LABEL version="4.0.0"
LABEL description="BlackSentinel Strike - Professional Penetration Testing Platform"

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install base tools + pentest essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Python
    python3 python3-pip python3-venv python3-tk \
    # Core pentest tools
    nmap masscan nikto sqlmap hydra whatweb dirb \
    # Network tools
    net-tools iputils-ping dnsutils whois tcpdump \
    # MAC/network manipulation
    macchanger \
    # Wordlists
    wordlists seclists \
    # Go-based tools (if available via apt)
    nuclei subfinder ffuf \
    # Additional tools
    curl wget git \
    # GUI dependencies (for tkinter/customtkinter)
    x11vnc xvfb \
    # Required shared libraries
    libgl1-mesa-glx libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Extract rockyou.txt if compressed
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gunzip /usr/share/wordlists/rockyou.txt.gz; \
    fi

# Install gobuster and dirsearch via Go or pip
RUN pip3 install --break-system-packages dirsearch 2>/dev/null || true

# Create app directory
WORKDIR /app

# Copy requirements first (layer cache)
COPY requirements.txt .
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create vault directory
RUN mkdir -p /root/.blacksentinel-strike/vault/scans && chmod 700 /root/.blacksentinel-strike/vault

# Environment
ENV DISPLAY=:0
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Expose VNC port (for headless deployment)
EXPOSE 5900

# Default: start Xvfb + VNC + app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
