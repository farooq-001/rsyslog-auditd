#!/bin/bash
##################
##Check root user#
##################
if [ "$USER" != "root" ]; then
    echo ""
    echo 'Invalid User!!! Please login as root and rerun the script.'
    echo ""
    exit 0
fi
########################
##Check Internet access#
########################
echo -n "Checking for Internet access..."
IP=$(curl -s ipinfo.io/ip 2> /dev/null)
if [[ $? -eq 0 ]]; then
    echo "Online."
    echo ""
else
    echo " Offline."
    echo ""
    echo "Check internet access and rerun script. Terminating Script!"
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
    echo "Cannot detect OS. /etc/os-release not found."
    exit 1
fi
echo "Detected OS: $OS_FLAVOR"
# Check rsyslog and auditd services
for svc in rsyslog auditd; do
    if ! systemctl list-unit-files | grep -q "^${svc}.service"; then
        echo "$svc service not available. Will install."
    else
        echo "$svc service available."
    fi
done
# Install or update for RPM-based systems (Rocky, RHEL, CentOS, Amazon Linux, Oracle Linux)
install_rpm() {
    local pkg_manager=$1
    echo "Installing rsyslog, audit, sendmail, wget..."
    $pkg_manager install rsyslog audit sendmail wget -y
    echo "Starting services..."
    systemctl enable rsyslog auditd sendmail
    systemctl start rsyslog auditd sendmail
}
# Install or update for Ubuntu
install_ubuntu() {
    echo "Installing rsyslog, auditd, sendmail, wget..."
    apt install rsyslog auditd sendmail wget -y
    echo "Starting services..."
    systemctl enable rsyslog auditd sendmail
    systemctl start rsyslog auditd sendmail
}
# Handle OS cases
case $OS in
    rocky|rhel|centos|amzn|ol)
        if [ "$OS" = "amzn" ] && [ "${VERSION_ID:0:1}" = "2" ] || [ "$OS" = "centos" ] && [[ "$VERSION_ID" =~ ^7 ]]; then
            install_rpm yum
        else
            install_rpm dnf
        fi
        ;;
    ubuntu)
        install_ubuntu
        ;;
    *)
        echo "Unsupported OS: $OS_FLAVOR"
        exit 1
        ;;
esac

##############################
# Ensure wget is installed    #
##############################
if ! command -v wget >/dev/null 2>&1; then
    echo "wget not found, installing wget..."
    if [[ "$OS" == "rhel" || "$OS" == "centos" || "$OS" == "rocky" || "$OS" == "amzn" || "$OS" == "ol" ]]; then
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y wget
        else
            yum install -y wget
        fi
    elif [[ "$OS" == "ubuntu" ]]; then
        apt install -y wget
    else
        echo "Unsupported OS for wget installation"
        exit 1
    fi
fi
echo

######################
# Parse -ip argument #
######################
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -ip) LOG_COLLECTOR_IP="$2"; shift 2 ;;
    *) echo "Unknown parameter passed: $1"; exit 1 ;;
  esac
done
if [[ -z "$LOG_COLLECTOR_IP" ]]; then
  echo "Usage: $0 -ip <LOG_COLLECTOR_IP>"
  exit 1
fi
##############################
# Paths to config files, backup
##############################
RSYSLOG_CONF="/etc/rsyslog.d/50-rsyslog-log-forward.conf"
AUDIT_RULES="/etc/audit/rules.d/audit.rules"
AUDIT_CONF="/etc/audit/auditd.conf"
BACKUP_DIR="/tmp"
TS=$(date +%Y%m%d-%H%M%S)
# Move existing files to /tmp with timestamp if they exist
[[ -f "$RSYSLOG_CONF" ]] && mv "$RSYSLOG_CONF" "$BACKUP_DIR/50-rsyslog-log-forward.conf.$TS"
[[ -f "$AUDIT_RULES" ]] && mv "$AUDIT_RULES" "$BACKUP_DIR/audit.rules.$TS"
[[ -f "$AUDIT_CONF" ]] && mv "$AUDIT_CONF" "$BACKUP_DIR/auditd.conf.$TS"
# Download files quietly
curl -L "https://raw.githubusercontent.com/farooq-001/rsyslog-auditd/master/50-rsyslog-log-forward.conf" -o "$RSYSLOG_CONF"
curl -L "https://raw.githubusercontent.com/farooq-001/rsyslog-auditd/master/audit.conf" -o "$AUDIT_CONF"
curl -L "https://raw.githubusercontent.com/farooq-001/rsyslog-auditd/master/audit.rules" -o "$AUDIT_RULES"

if [[ ! -f "$RSYSLOG_CONF" ]]; then
  echo "Config file $RSYSLOG_CONF does not exist after download."
  exit 1
fi
# Replace <LOG_COLLECTOR_IP> quietly
sed -i "s|<LOG_COLLECTOR_IP>|$LOG_COLLECTOR_IP|g" "$RSYSLOG_CONF"
echo "Config Files Updated successfully."
echo "1.$RSYSLOG_CONF"
echo "2.$AUDIT_RULES"
echo "3.$AUDIT_CONF"
echo ""
echo "[+] Restarting services..."
systemctl restart rsyslog
kill -9 $(systemctl show -p MainPID --value auditd.service)
systemctl restart auditd
if [ $? -eq 4 ]; then
    service auditd reload
    pint=$?
    echo "Reload command exit code: $pint"
    echo "print value: $pint"
fi
echo "[+] Checking service status..."
systemctl is-active --quiet auditd && echo "[OK] auditd is running"
systemctl is-active --quiet rsyslog && echo "[OK] rsyslog is running"

###############################################
# SELinux config for RHEL and CentOS Stream 10
###############################################
if [[ "$OS" == "rhel" || "$OS" == "centos" ]]; then
    echo "[+] Applying RHEL/CentOS-specific SELinux policy for rsyslog..."
    dnf install -y policycoreutils-python-utils
    ausearch -m avc -c rsyslogd --raw | audit2allow -M rsyslog_audit_access
    semodule -i rsyslog_audit_access.pp
    semanage permissive -a syslogd_t
    systemctl restart rsyslog
fi

########################################
# Check if the OS is Ubuntu
########################################
if [ "$OS" = "ubuntu" ]; then
    echo "Ubuntu detected. Running AppArmor update script..."

    # Define the AppArmor profile file
    APPARMOR_PROFILE="/etc/apparmor.d/usr.sbin.rsyslogd"

    # Check if the AppArmor profile file exists
    if [[ ! -f "$APPARMOR_PROFILE" ]]; then
      echo "Error: AppArmor profile $APPARMOR_PROFILE does not exist."
      exit 1
    fi

    # Find all log files under /var/log/
    find /var/log/ -type f -name "*.log" | while read -r logfile; do
      echo "Processing $logfile..."

      # Check if the log file path is already in the AppArmor profile
      if grep -Fx "  $logfile r," "$APPARMOR_PROFILE" > /dev/null; then
        echo "  $logfile is already in $APPARMOR_PROFILE, skipping..."
      else
        # Add the log file path to the AppArmor profile
        echo "Adding $logfile to $APPARMOR_PROFILE..."
        sed -i "/# 'r' is needed when using imfile/a \  $logfile r," "$APPARMOR_PROFILE"
      fi
    done

    # Reload the AppArmor profile
    echo "Reloading AppArmor profile..."
    apparmor_parser -r "$APPARMOR_PROFILE"

    # Reload system daemons
    echo "Reloading system daemons..."
    systemctl daemon-reload

    # Reload the AppArmor service
    echo "Reloading AppArmor service..."
    systemctl reload apparmor

    # Modify /etc/audit/auditd.conf to change log_group
    AUDIT_CONF="/etc/audit/auditd.conf"
    if [[ -f "$AUDIT_CONF" ]]; then
        echo "Modifying $AUDIT_CONF..."
        sed -i 's/log_group = root/log_group = adm/' "$AUDIT_CONF"
    else
        echo "Error: $AUDIT_CONF does not exist."
        exit 1
    fi

    # Modify /etc/rsyslog.d/50-rsyslog-log-forward.conf to uncomment WorkDirectory
    RSYSLOG_CONF="/etc/rsyslog.d/50-rsyslog-log-forward.conf"
    if [[ -f "$RSYSLOG_CONF" ]]; then
        echo "Modifying $RSYSLOG_CONF..."
        sed -i 's/#$WorkDirectory \/var\/spool\/rsyslog/$WorkDirectory \/var\/spool\/rsyslog/' "$RSYSLOG_CONF"
    else
        echo "Error: $RSYSLOG_CONF does not exist."
        exit 1
    fi

    # Add syslog user to adm group
    echo "Adding syslog user to adm group..."
    usermod -aG adm syslog
    
    # Create /var/log/audit directory if it doesn't exist
    echo "Creating /var/log/audit directory..."
    mkdir -p /var/log/audit    /var/lib/rsyslog
      
    # Set ownership and permissions for /var/log/audit
    echo "Setting ownership and permissions for /var/log/audit..."
    chown root:adm /var/log/audit
    chmod 750 /var/log/audit

    # Set permissions and group for /var/log/audit/audit.log
    if [[ -f "/var/log/audit/audit.log" ]]; then
        echo "Setting permissions and group for /var/log/audit/audit.log..."
        chmod 640 /var/log/audit/audit.log
        chgrp adm /var/log/audit/audit.log
    else
        echo "Warning: /var/log/audit/audit.log does not exist, skipping permissions and group change."
    fi

    # Restart rsyslog and auditd services
    echo "Restarting rsyslog and auditd services..."
    systemctl restart rsyslog auditd.service

    echo "Script completed successfully."
fi

######################################
# Check if Ubuntu 18.04.6, 18.04.4 or 20.04.6
######################################
echo ""
echo "######################################"
echo "# Check if Ubuntu 18.04.6 or 18.04.4 or 20.04.6 #"
echo "######################################"

if [[ "$OS" == "ubuntu" && ( "$VERSION_ID" == "18.04" || "$VERSION_ID" == "20.04" ) ]]; then

    echo "Target OS detected. Downloading auditd.conf..."

    AUDIT_CONF="/etc/audit/auditd.conf"

    # Backup old file
    [ -f "$AUDIT_CONF" ] && sudo cp "$AUDIT_CONF" "$AUDIT_CONF.bak.$(date +%Y%m%d_%H%M%S)"

    # Download and replace
    sudo curl -L "https://raw.githubusercontent.com/farooq-001/rsyslog-auditd/master/auditd-18.conf" -o "$AUDIT_CONF"
    
    echo ""
    echo "auditd.conf updated successfully!"

    # Restart rsyslog and auditd services
    echo "Restarting rsyslog and auditd services..."
    sudo systemctl restart rsyslog auditd.service 2>/dev/null || echo "Warning: Some services failed to restart."

else
    echo "Not Ubuntu 18.04.6, 18.04.4, or 20.04.6 → No action taken."
fi

echo "########################################"
echo "[+] Configuration applied successfully."
echo "########################################"
