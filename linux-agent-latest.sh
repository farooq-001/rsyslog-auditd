#!/bin/bash
##################
##Check root user#
##################
if [ "$USER" != "root" ]; then
    echo ""
    echo "⚠️  Invalid User!!! Please login as root and rerun the script."
    echo ""
    exit 1
fi

########################
##Check Internet access#
########################
echo -n "Checking for Internet access..."
if curl -s ipinfo.io/ip >/dev/null 2>&1; then
    echo "Online."
    echo ""
else
    echo " Offline."
    echo ""
    echo "⚠️  Check internet access and rerun script. Terminating Script!"
    exit 1
fi

echo "#########################"
echo "# Detect OS and version #"
echo "#########################"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION_ID=$VERSION_ID
    OS_FLAVOR="$PRETTY_NAME"
else
    echo "⚠️  Cannot detect OS. /etc/os-release not found."
    exit 1
fi

echo ""
echo "🐧 Detected OS: $OS_FLAVOR"
echo ""

#########################
# Check rsyslog/auditd  #
#########################
for svc in rsyslog auditd; do
    if ! systemctl list-unit-files | grep -q "^${svc}.service"; then
        echo "$svc service not available. Will install."
    else
        echo "$svc service available."
    fi
done

#########################
# Install Dependencies  #
#########################
install_rpm() {
    local pkg_manager=$1
    echo "Installing rsyslog, audit, sendmail, wget..."
    $pkg_manager install -y rsyslog audit sendmail wget
    echo "Starting services..."
    systemctl enable rsyslog auditd sendmail
    systemctl start rsyslog auditd sendmail
}

install_ubuntu() {
    echo "Installing rsyslog, auditd, sendmail, wget..."
    apt install -y rsyslog auditd sendmail wget
    echo "Starting services..."
    systemctl enable rsyslog auditd sendmail
    systemctl start rsyslog auditd sendmail
}

case $OS in
    rocky|rhel|centos|amzn|ol)
        if { [ "$OS" = "amzn" ] && [[ "${VERSION_ID:0:1}" = "2" ]]; } || { [ "$OS" = "centos" ] && [[ "$VERSION_ID" =~ ^7 ]]; }; then
            install_rpm yum
        else
            install_rpm dnf
        fi
        ;;
    ubuntu)
        install_ubuntu
        ;;
    *)
        echo "⚠️ Unsupported OS: $OS_FLAVOR"
        exit 1
        ;;
esac

##############################
# Ensure wget is installed   #
##############################
if ! command -v wget >/dev/null 2>&1; then
    echo "wget not found, installing..."
    if [[ "$OS" =~ ^(rhel|centos|rocky|amzn|ol)$ ]]; then
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y wget
        else
            yum install -y wget
        fi
    elif [[ "$OS" == "ubuntu" ]]; then
        apt install -y wget
    fi
fi
echo

######################
# Parse -ip argument #
######################
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -ip) LOG_COLLECTOR_IP="$2"; shift 2 ;;
    *) echo "Usage: $0 -ip <LOG_COLLECTOR_IP>"; exit 1 ;;
  esac
done
if [[ -z "$LOG_COLLECTOR_IP" ]]; then
  echo "Usage: $0 -ip <LOG_COLLECTOR_IP>"
  exit 1
fi

##############################
# Config paths and backups   #
##############################
RSYSLOG_CONF="/etc/rsyslog.d/50-rsyslog-log-forward.conf"
AUDIT_RULES="/etc/audit/rules.d/audit.rules"
AUDIT_CONF="/etc/audit/auditd.conf"
BACKUP_DIR="/tmp"
TS=$(date +%Y%m%d-%H%M%S)

[[ -f "$RSYSLOG_CONF" ]] && mv "$RSYSLOG_CONF" "$BACKUP_DIR/50-rsyslog-log-forward.conf.$TS"
[[ -f "$AUDIT_RULES" ]] && mv "$AUDIT_RULES" "$BACKUP_DIR/audit.rules.$TS"
[[ -f "$AUDIT_CONF" ]] && mv "$AUDIT_CONF" "$BACKUP_DIR/auditd.conf.$TS"

# Download new configs
curl -sSL "https://raw.githubusercontent.com/farooq-001/rsyslog-auditd/master/50-rsyslog-log-forward.conf" -o "$RSYSLOG_CONF"
curl -sSL "https://raw.githubusercontent.com/farooq-001/rsyslog-auditd/master/audit.conf" -o "$AUDIT_CONF"
curl -sSL "https://raw.githubusercontent.com/farooq-001/rsyslog-auditd/master/audit.rules" -o "$AUDIT_RULES"

if [[ ! -f "$RSYSLOG_CONF" ]]; then
  echo "Config file $RSYSLOG_CONF not found after download."
  exit 1
fi

sed -i "s|<LOG_COLLECTOR_IP>|$LOG_COLLECTOR_IP|g" "$RSYSLOG_CONF"

echo "[+] Config Files Updated successfully."
echo "[1] $RSYSLOG_CONF"
echo "[2] $AUDIT_RULES"
echo "[3] $AUDIT_CONF"
echo ""

#############################
# Restart services safely   #
#############################
echo "[+] Restarting services..."
systemctl restart rsyslog

MAINPID=$(systemctl show -p MainPID auditd.service | cut -d'=' -f2)
if [[ -n "$MAINPID" && "$MAINPID" != "0" ]]; then
    kill -9 "$MAINPID" 2>/dev/null
fi
systemctl restart auditd || service auditd reload

echo "[+] Checking service status..."
systemctl is-active --quiet auditd && echo "[+] auditd is running"
systemctl is-active --quiet rsyslog && echo "[+] rsyslog is running"

########################################
# Ubuntu 24.04 AppArmor adjustments    #
########################################
if [[ "$OS" == "ubuntu" && "$VERSION_ID" == "24.04" ]]; then    
    echo "Ubuntu detected. Running AppArmor update script..."

    APPARMOR_PROFILE="/etc/apparmor.d/usr.sbin.rsyslogd"
    if [[ -f "$APPARMOR_PROFILE" ]]; then
        find /var/log/ -type f -name "*.log" | while read -r logfile; do
            if ! grep -Fx "  $logfile r," "$APPARMOR_PROFILE" >/dev/null; then
                echo "Adding $logfile to $APPARMOR_PROFILE..."
                sed -i "/# 'r' is needed when using imfile/a \  $logfile r," "$APPARMOR_PROFILE"
            fi
        done
        apparmor_parser -r "$APPARMOR_PROFILE"
        systemctl reload apparmor
    else
        echo "AppArmor profile not found — skipping."
    fi

    sed -i 's/log_group = root/log_group = adm/' "$AUDIT_CONF"
    sed -i 's/^#\$WorkDirectory.*/\$WorkDirectory \/var\/spool\/rsyslog/' "$RSYSLOG_CONF"

    usermod -aG adm syslog
    mkdir -p /var/log/audit /var/lib/rsyslog
    chown root:adm /var/log/audit
    chmod 750 /var/log/audit

    if [[ -f "/var/log/audit/audit.log" ]]; then
        chmod 640 /var/log/audit/audit.log
        chgrp adm /var/log/audit/audit.log
    fi

    systemctl restart rsyslog auditd
    echo "Ubuntu AppArmor section completed."
fi

##################################################
#   Check Auditd version 2.8.5                   #
##################################################
RSYSLOGVERSION=$( (rsyslogd -v 2>/dev/null || rsyslogd --version 2>/dev/null) | awk '/^rsyslogd /{print $2}' )
VERSION=$(auditctl -v | awk '{print $3}')
TARGET_VERSION="2.8.5"

if [ "$VERSION" = "$TARGET_VERSION" ]; then
    echo "[+] auditctl version $VERSION detected — updating auditd.conf..."
    cp "$AUDIT_CONF" "$AUDIT_CONF.bak.$(date +%Y%m%d_%H%M%S)"
    curl -sSL "https://raw.githubusercontent.com/farooq-001/rsyslog-auditd/master/auditd-18.conf" -o "$AUDIT_CONF"

    if [[ ! ("$OS" == "centos" && "$VERSION_ID" == "7") ]]; then 
        sed -i 's/^#\$WorkDirectory.*/\$WorkDirectory \/var\/spool\/rsyslog/' /etc/rsyslog.d/50-rsyslog-log-forward.conf
    fi    

    systemctl daemon-reload
    systemctl restart rsyslog
    MAINPID=$(systemctl show -p MainPID auditd.service | cut -d'=' -f2)
    [[ -n "$MAINPID" && "$MAINPID" != "0" ]] && kill -9 "$MAINPID" 2>/dev/null
    systemctl restart auditd

    echo "[+] Services restarted successfully."
else
    echo "[+] auditctl version ($VERSION) does not match required version ($TARGET_VERSION). Skipping version-specific config."
fi


###############################################
# SELinux config for RHEL and CentOS Stream 10
###############################################

if [[ ("$OS" == "rhel" || "$OS" == "centos") && "$VERSION_ID" != "7" ]]; then
    echo "[+] Applying RHEL/CentOS (non–7) specific SELinux policy for rsyslog..."
    dnf install -y policycoreutils-python-utils
    ausearch -m avc -c rsyslogd --raw | audit2allow -M rsyslog_audit_access
    semodule -i rsyslog_audit_access.pp
    semanage permissive -a syslogd_t
    systemctl restart rsyslog

elif [[ "$OS" == "centos" && "$(rpm -E %{rhel})" == "7" ]]; then
    echo "[+] Applying CentOS 7-specific SELinux policy for rsyslog..."
    yum install -y policycoreutils-python
    ausearch -m avc -c rsyslogd --raw | audit2allow -M rsyslog_audit_access
    semodule -i rsyslog_audit_access.pp
    semanage permissive -a syslogd_t
    systemctl restart rsyslog
fi

echo ""
echo "[+] Checking status..."
echo "[+] auditctl version: $VERSION"
echo "[+] rsyslog version: $RSYSLOGVERSION"
echo "[+] Detected OS: $OS_FLAVOR"
echo ""
systemctl is-active --quiet auditd && echo "[OK] auditd  is running  12513 TCP"
systemctl is-active --quiet rsyslog && echo "[OK] rsyslog is running 12514 UDP "
echo ""

echo "########################################"
echo "✅ Configuration applied successfully  "
echo "########################################"
