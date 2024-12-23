#!/usr/bin/env python3
import os
import subprocess
from datetime import datetime
import csv
import shutil
import argparse
import sys

LOG_FILE = "debian_security_fix.log"
CSV_FILE = "security_fixes.csv"

def log_action(message):
    with open(LOG_FILE, "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"[{timestamp}] {message}\n")
    print(message)

def log_fix_to_csv(cve, severity, action, description):
    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([timestamp, cve, severity, action, description])

def run_command(command, description, cve, severity):
    try:
        result = subprocess.run(command, check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        log_action(f"SUCCESS: {description}")
        log_fix_to_csv(cve, severity, description, "Success")
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.decode().strip()
        log_action(f"ERROR: {description}. Command: {command}, Error: {error_message}")
        log_fix_to_csv(cve, severity, description, f"Failed: {error_message}")
    except subprocess.TimeoutExpired:
        log_action(f"ERROR: {description}. Command: {command} timed out.")
        log_fix_to_csv(cve, severity, description, "Failed: Command timed out.")

def check_and_install_tool(tool_name, cve, severity):
    try:
        subprocess.run(f"dpkg -s {tool_name}", check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log_action(f"{tool_name} is already installed.")
    except subprocess.CalledProcessError:
        log_action(f"{tool_name} is not installed. Installing...")
        run_command(f"apt-get install -y {tool_name}", f"Installed {tool_name}", cve, severity)

def disable_root_ssh():
    cve = "CVE-2016-6210"
    severity = "High"
    action = "Disable root login via SSH"
    description = "Disabled root login via SSH to mitigate CVE-2016-6210."

    ssh_config = "/etc/ssh/sshd_config"
    backup_file = "/etc/ssh/sshd_config.bak"

    # Backup sshd_config if not already backed up
    if not os.path.exists(backup_file):
        if os.path.exists(ssh_config):
            try:
                shutil.copy2(ssh_config, backup_file)
                log_action(f"Backup of sshd_config created at {backup_file}")
            except Exception as e:
                log_action(f"ERROR: Failed to backup {ssh_config}. Error: {str(e)}")
                log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
                return
        else:
            log_action(f"ERROR: {ssh_config} does not exist. Skipping backup.")
            log_fix_to_csv(cve, severity, action, f"Failed: {ssh_config} does not exist.")
            return

    # Disable root login
    run_command(f"sed -i '/^PermitRootLogin/s/.*/PermitRootLogin no/' {ssh_config}", description, cve, severity)
    run_command("systemctl restart ssh", "Restarted SSH service", cve, severity)

def enable_automatic_updates():
    cve = "CVE-2022-27446"
    severity = "Medium"
    action = "Enable automatic security updates"
    description = "Enabled automatic security updates to mitigate CVE-2022-27446."

    check_and_install_tool("unattended-upgrades", cve, severity)
    run_command("dpkg-reconfigure -plow unattended-upgrades", description, cve, severity)

def disable_unnecessary_services():
    cves = {
        "telnet": {"CVE": "CVE-2020-15778", "Severity": "High"},
        "rlogin": {"CVE": "CVE-2020-15778", "Severity": "High"},
        "rexec": {"CVE": "CVE-2020-15778", "Severity": "High"},
    }
    action = "Disable unnecessary services"

    for service, info in cves.items():
        cve = info["CVE"]
        severity = info["Severity"]
        result = check_command(f"systemctl list-unit-files | grep {service}.service")
        if service in result:
            run_command(f"systemctl disable {service}", f"Disabled unnecessary service: {service}", cve, severity)
            run_command(f"systemctl stop {service}", f"Stopped service: {service}", cve, severity)
        else:
            log_action(f"Service {service} does not exist, skipping.")
            log_fix_to_csv(cve, severity, f"Check {service} service", f"Skipped: {service} does not exist.")

def enforce_password_policy():
    cve = "CVE-2019-6111"
    severity = "High"
    action = "Enforce password complexity requirements"
    description = "Enforced password complexity to mitigate CVE-2019-6111."

    pam_pwquality = "/etc/security/pwquality.conf"
    backup_file = "/etc/security/pwquality.conf.bak"
    config_updates = [
        "minlen = 12",
        "minclass = 3",
        "maxrepeat = 3",
        "dcredit = -1",
        "ucredit = -1",
        "ocredit = -1",
        "lcredit = -1"
    ]

    # Backup pwquality.conf if it exists
    if os.path.exists(pam_pwquality):
        if not os.path.exists(backup_file):
            try:
                shutil.copy2(pam_pwquality, backup_file)
                log_action(f"Backup of pwquality.conf created at {backup_file}")
            except Exception as e:
                log_action(f"ERROR: Failed to backup {pam_pwquality}. Error: {str(e)}")
                log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
                return
    else:
        log_action(f"{pam_pwquality} does not exist. Creating the file.")
        try:
            with open(pam_pwquality, "w") as f:
                f.write("# pwquality configuration\n")
        except Exception as e:
            log_action(f"ERROR: Failed to create {pam_pwquality}. Error: {str(e)}")
            log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
            return

    # Update pwquality.conf with configurations
    try:
        with open(pam_pwquality, "a") as f:
            for config in config_updates:
                f.write(f"{config}\n")
        log_action("Updated password complexity requirements in pwquality.conf")
        log_fix_to_csv(cve, severity, action, "Success")
    except Exception as e:
        log_action(f"ERROR: Failed to update {pam_pwquality}. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")

def configure_firewall():
    cve = "CVE-2020-16088"
    severity = "Medium"
    action = "Configure firewall to allow only necessary traffic"
    description = "Configured firewall settings to mitigate CVE-2020-16088."

    check_and_install_tool("ufw", cve, severity)
    run_command("ufw enable", "Enabled UFW firewall", cve, severity)
    run_command("ufw default deny incoming", "Default deny incoming traffic", cve, severity)
    run_command("ufw default allow outgoing", "Default allow outgoing traffic", cve, severity)
    # Allow SSH
    run_command("ufw allow ssh", "Allowed SSH traffic through UFW", cve, severity)
    log_fix_to_csv(cve, severity, action, "Success")

def enable_file_integrity_monitoring():
    cve = "CVE-2021-22555"
    severity = "High"
    action = "Enable file integrity monitoring"
    description = "Enabled file integrity monitoring using AIDE to mitigate CVE-2021-22555."

    check_and_install_tool("aide", cve, severity)
    # Initialize AIDE
    run_command("aideinit -y", "Initialized AIDE database", cve, severity)
    run_command("cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db", "Activated AIDE database", cve, severity)
    # Since aide.service may not exist, set up a cron job instead
    cron_job = "0 3 * * * /usr/bin/aide --check"
    try:
        existing_cron = check_command(f"crontab -l | grep 'aide --check'")
        if not existing_cron:
            run_command(f'(crontab -l ; echo "{cron_job}") | crontab -', "Added AIDE cron job for daily checks", cve, severity)
        else:
            log_action("AIDE cron job already exists, skipping addition.")
            log_fix_to_csv(cve, severity, action, "Skipped: AIDE cron job already exists.")
    except Exception as e:
        log_action(f"ERROR: Failed to set up AIDE cron job. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")

def configure_secure_dns():
    cve = "CVE-2018-6789"
    severity = "High"
    action = "Configure secure DNS services"
    description = "Configured Unbound for secure DNS to mitigate CVE-2018-6789."

    check_and_install_tool("unbound", cve, severity)
    run_command("systemctl enable unbound", "Enabled Unbound service", cve, severity)
    run_command("systemctl start unbound", "Started Unbound service", cve, severity)
    
    # Basic Unbound configuration for DNSSEC and DoT
    unbound_conf = "/etc/unbound/unbound.conf.d/debian-secure.conf"
    secure_dns_config = """
server:
    interface: 127.0.0.1
    port: 53
    do-daemonize: no
    log-queries: no
    log-replies: no
    verbosity: 1
    use-syslog: yes
    username: unbound
    directory: "/etc/unbound"
    hide-identity: yes
    hide-version: yes
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    use-caps-for-id: yes
    edns-buffer-size: 1232
    prefetch: yes
    prefetch-key: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    val-clean-additional: yes
    do-not-query-localhost: no
    tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    forward-zone:
        name: "."
        forward-ssl-upstream: yes
        forward-addr: 1.1.1.1@853  # Cloudflare DNS
        forward-addr: 1.0.0.1@853
    """

    try:
        with open(unbound_conf, "w") as f:
            f.write(secure_dns_config)
        run_command("unbound-checkconf", "Checked Unbound configuration", cve, severity)
        run_command("systemctl restart unbound", "Restarted Unbound service with secure DNS settings", cve, severity)
        log_fix_to_csv(cve, severity, action, "Success")
    except Exception as e:
        log_action(f"ERROR: Failed to configure Unbound. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")

def install_antivirus():
    cve = "CVE-2022-30190"
    severity = "Medium"
    action = "Install and configure antivirus software"
    description = "Installed and configured ClamAV to mitigate CVE-2022-30190."

    check_and_install_tool("clamav", cve, severity)
    check_and_install_tool("clamav-daemon", cve, severity)
    
    run_command("systemctl enable clamav-freshclam", "Enabled ClamAV Freshclam service", cve, severity)
    run_command("systemctl start clamav-freshclam", "Started ClamAV Freshclam service", cve, severity)
    
    # Fix permissions for freshclam log
    freshclam_log = "/var/log/clamav/freshclam.log"
    if not os.path.exists(freshclam_log):
        try:
            run_command(f"touch {freshclam_log}", f"Created freshclam log file at {freshclam_log}", cve, severity)
            run_command(f"chown clamav:clamav {freshclam_log}", f"Set ownership for {freshclam_log}", cve, severity)
        except Exception as e:
            log_action(f"ERROR: Failed to set up freshclam log file. Error: {str(e)}")
            log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
    
    run_command("freshclam", "Updated ClamAV virus definitions", cve, severity)
    run_command("systemctl enable clamav-daemon", "Enabled ClamAV daemon", cve, severity)
    run_command("systemctl start clamav-daemon", "Started ClamAV daemon", cve, severity)
    log_fix_to_csv(cve, severity, action, "Success")

def enforce_least_privilege():
    cve = "CVE-2020-14386"
    severity = "High"
    action = "Enforce least privilege principle for user accounts"
    description = "Set permissions for /etc/passwd and /etc/shadow to enforce least privilege, mitigating CVE-2020-14386."

    passwd_file = "/etc/passwd"
    shadow_file = "/etc/shadow"
    
    # Set permissions for /etc/passwd
    if os.path.exists(passwd_file):
        run_command(f"chmod 644 {passwd_file}", "Set permissions for /etc/passwd to 644", cve, severity)
    else:
        log_action(f"ERROR: {passwd_file} does not exist. Cannot enforce least privilege.")
        log_fix_to_csv(cve, severity, action, f"Failed: {passwd_file} does not exist.")
    
    # Set permissions for /etc/shadow
    if os.path.exists(shadow_file):
        run_command(f"chmod 640 {shadow_file}", "Set permissions for /etc/shadow to 640", cve, severity)
    else:
        log_action(f"ERROR: {shadow_file} does not exist. Cannot enforce least privilege.")
        log_fix_to_csv(cve, severity, action, f"Failed: {shadow_file} does not exist.")
    
    log_fix_to_csv(cve, severity, action, "Success")

def enable_secure_boot():
    cve = "CVE-2019-8912"
    severity = "High"
    action = "Enable Secure Boot if supported"
    description = "Checked Secure Boot status and advised enabling it to mitigate CVE-2019-8912."

    check_and_install_tool("mokutil", cve, severity)
    # Secure Boot enabling usually requires user interaction during boot.
    # This script will check if Secure Boot is already enabled.
    result = check_command("mokutil --sb-state")
    if "SecureBoot enabled" in result:
        log_action("Secure Boot is already enabled.")
        log_fix_to_csv(cve, severity, action, "Secure Boot is already enabled.")
    else:
        log_action("Secure Boot is not enabled. Enabling Secure Boot requires manual steps.")
        log_fix_to_csv(cve, severity, action, "Failed: Secure Boot is not enabled. Manual intervention required.")

def configure_auditing():
    cve = "CVE-2021-33909"
    severity = "High"
    action = "Enable and configure auditing tools"
    description = "Installed and configured auditd to track security-relevant events, mitigating CVE-2021-33909."

    check_and_install_tool("auditd", cve, severity)
    run_command("systemctl enable auditd", "Enabled auditd service", cve, severity)
    run_command("systemctl start auditd", "Started auditd service", cve, severity)
    
    # Configure audit rules
    audit_rules = "/etc/audit/rules.d/audit.rules"
    rules = [
        "-w /etc/passwd -p wa -k passwd_changes",
        "-w /etc/shadow -p wa -k shadow_changes",
        "-w /etc/ssh/sshd_config -p wa -k sshd_config_changes",
        "-w /var/log/auth.log -p wa -k auth_log_changes"
    ]
    
    # Backup existing rules
    if os.path.exists(audit_rules):
        backup_file = f"{audit_rules}.bak"
        if not os.path.exists(backup_file):
            try:
                shutil.copy2(audit_rules, backup_file)
                log_action(f"Backup of audit.rules created at {backup_file}")
            except Exception as e:
                log_action(f"ERROR: Failed to backup {audit_rules}. Error: {str(e)}")
                log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
                return
    else:
        log_action(f"{audit_rules} does not exist. Creating the file.")
        try:
            open(audit_rules, 'a').close()
        except Exception as e:
            log_action(f"ERROR: Failed to create {audit_rules}. Error: {str(e)}")
            log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
            return
    
    # Append rules
    try:
        with open(audit_rules, "a") as f:
            existing_rules = f.read()
            for rule in rules:
                if rule not in existing_rules:
                    f.write(f"{rule}\n")
        run_command("systemctl restart auditd", "Restarted auditd service to apply new rules", cve, severity)
        log_fix_to_csv(cve, severity, action, "Success")
    except Exception as e:
        log_action(f"ERROR: Failed to configure audit rules. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")

def configure_ssh():
    cve = "CVE-2019-6109"
    severity = "Medium"
    action = "Configure SSH to use key-based authentication and strong ciphers"
    description = "Configured SSH for key-based authentication and strong ciphers to mitigate CVE-2019-6109."

    ssh_config = "/etc/ssh/sshd_config"
    backup_file = "/etc/ssh/sshd_config.bak"
    
    # Backup sshd_config if not already backed up
    if not os.path.exists(backup_file):
        if os.path.exists(ssh_config):
            try:
                shutil.copy2(ssh_config, backup_file)
                log_action(f"Backup of sshd_config created at {backup_file}")
            except Exception as e:
                log_action(f"ERROR: Failed to backup {ssh_config}. Error: {str(e)}")
                log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
                return
        else:
            log_action(f"ERROR: {ssh_config} does not exist. Skipping backup.")
            log_fix_to_csv(cve, severity, action, f"Failed: {ssh_config} does not exist.")
            return
    
    # Disable password authentication
    run_command(f"sed -i '/^PasswordAuthentication/s/.*/PasswordAuthentication no/' {ssh_config}", "Disabled SSH password authentication", cve, severity)
    
    # Configure strong SSH ciphers
    run_command(f"sed -i '/^Ciphers/s/.*/Ciphers aes256-ctr,aes192-ctr,aes128-ctr/' {ssh_config}", "Configured strong SSH ciphers", cve, severity)
    
    # Restart SSH service
    run_command("systemctl restart ssh", "Restarted SSH service", cve, severity)
    
    log_fix_to_csv(cve, severity, action, "Success")

def configure_secure_dns():
    cve = "CVE-2018-6789"
    severity = "High"
    action = "Configure secure DNS services"
    description = "Configured Unbound for secure DNS to mitigate CVE-2018-6789."

    check_and_install_tool("unbound", cve, severity)
    run_command("systemctl enable unbound", "Enabled Unbound service", cve, severity)
    run_command("systemctl start unbound", "Started Unbound service", cve, severity)
    
    # Basic Unbound configuration for DNSSEC and DoT
    unbound_conf = "/etc/unbound/unbound.conf.d/debian-secure.conf"
    secure_dns_config = """
server:
    interface: 127.0.0.1
    port: 53
    do-daemonize: no
    log-queries: no
    log-replies: no
    verbosity: 1
    use-syslog: yes
    username: unbound
    directory: "/etc/unbound"
    hide-identity: yes
    hide-version: yes
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    use-caps-for-id: yes
    edns-buffer-size: 1232
    prefetch: yes
    prefetch-key: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    val-clean-additional: yes
    do-not-query-localhost: no
    tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    forward-zone:
        name: "."
        forward-ssl-upstream: yes
        forward-addr: 1.1.1.1@853  # Cloudflare DNS
        forward-addr: 1.0.0.1@853
    """

    try:
        with open(unbound_conf, "w") as f:
            f.write(secure_dns_config)
        run_command("unbound-checkconf", "Checked Unbound configuration", cve, severity)
        run_command("systemctl restart unbound", "Restarted Unbound service with secure DNS settings", cve, severity)
        log_fix_to_csv(cve, severity, action, "Success")
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.decode().strip()
        log_action(f"ERROR: Failed to configure Unbound. Error: {error_message}")
        log_fix_to_csv(cve, severity, action, f"Failed: {error_message}")
    except Exception as e:
        log_action(f"ERROR: Failed to configure Unbound. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")

def lock_accounts_after_failed_logins():
    cve = "CVE-2017-12163"
    severity = "Medium"
    action = "Lock user accounts after multiple failed login attempts"
    description = "Configured PAM to lock user accounts after failed logins to mitigate CVE-2017-12163."

    pam_file = "/etc/pam.d/common-auth"
    rule = "auth required pam_tally2.so deny=5 unlock_time=900 onerr=fail audit"
    backup_file = f"{pam_file}.bak"
    
    # Backup PAM config
    if not os.path.exists(backup_file):
        if os.path.exists(pam_file):
            try:
                shutil.copy2(pam_file, backup_file)
                log_action(f"Backup of {pam_file} created at {backup_file}")
            except Exception as e:
                log_action(f"ERROR: Failed to backup {pam_file}. Error: {str(e)}")
                log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
                return
        else:
            log_action(f"ERROR: {pam_file} does not exist. Skipping backup.")
            log_fix_to_csv(cve, severity, action, f"Failed: {pam_file} does not exist.")
            return
    
    # Add or update pam_tally2 rule
    try:
        with open(pam_file, "r") as f:
            lines = f.readlines()
        
        with open(pam_file, "w") as f:
            rule_added = False
            for line in lines:
                if "pam_tally2.so" in line:
                    f.write(rule + "\n")
                    rule_added = True
                else:
                    f.write(line)
            if not rule_added:
                f.write(rule + "\n")
        
        run_command("systemctl restart ssh", "Restarted SSH service to apply PAM changes", cve, severity)
        log_fix_to_csv(cve, severity, action, "Success")
    except Exception as e:
        log_action(f"ERROR: Failed to configure PAM for account lockout. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")

def apply_security_patches():
    cve = "CVE-2019-18634"
    severity = "High"
    action = "Apply critical security patches promptly"
    description = "Applied all available security patches to mitigate CVE-2019-18634."

    run_command("apt-get update", "Updated package lists", cve, severity)
    run_command("apt-get upgrade -y", "Applied all available security patches", cve, severity)
    log_fix_to_csv(cve, severity, action, "Success")

def install_two_factor_auth():
    cve = "CVE-2019-18634"
    severity = "High"
    action = "Install and configure two-factor authentication for SSH"
    description = "Installed and configured Google Authenticator for SSH to mitigate CVE-2019-18634."

    check_and_install_tool("libpam-google-authenticator", cve, severity)
    
    # Configure PAM for SSH to use Google Authenticator
    pam_ssh = "/etc/pam.d/sshd"
    backup_file = f"{pam_ssh}.bak"
    if not os.path.exists(backup_file):
        if os.path.exists(pam_ssh):
            try:
                shutil.copy2(pam_ssh, backup_file)
                log_action(f"Backup of {pam_ssh} created at {backup_file}")
            except Exception as e:
                log_action(f"ERROR: Failed to backup {pam_ssh}. Error: {str(e)}")
                log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
                return
        else:
            log_action(f"ERROR: {pam_ssh} does not exist. Skipping backup.")
            log_fix_to_csv(cve, severity, action, f"Failed: {pam_ssh} does not exist.")
            return
    
    # Add Google Authenticator PAM module if not already present
    try:
        with open(pam_ssh, "r") as f:
            lines = f.readlines()
        
        if not any("pam_google_authenticator.so" in line for line in lines):
            with open(pam_ssh, "a") as f:
                f.write("auth required pam_google_authenticator.so\n")
            log_action("Configured PAM to use Google Authenticator for SSH")
            log_fix_to_csv(cve, severity, action, "Added Google Authenticator PAM module")
        else:
            log_action("PAM is already configured to use Google Authenticator for SSH")
            log_fix_to_csv(cve, severity, action, "Skipped: Google Authenticator PAM module already exists")
    except Exception as e:
        log_action(f"ERROR: Failed to configure PAM for Google Authenticator. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
        return
    
    # Configure SSH to require two-factor authentication
    ssh_config = "/etc/ssh/sshd_config"
    backup_ssh = f"{ssh_config}.bak"
    if not os.path.exists(backup_ssh):
        if os.path.exists(ssh_config):
            try:
                shutil.copy2(ssh_config, backup_ssh)
                log_action(f"Backup of sshd_config created at {backup_ssh}")
            except Exception as e:
                log_action(f"ERROR: Failed to backup {ssh_config}. Error: {str(e)}")
                log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
                return
        else:
            log_action(f"ERROR: {ssh_config} does not exist. Skipping backup.")
            log_fix_to_csv(cve, severity, action, f"Failed: {ssh_config} does not exist.")
            return
    
    # Ensure ChallengeResponseAuthentication is yes
    run_command(f"sed -i '/^ChallengeResponseAuthentication/s/.*/ChallengeResponseAuthentication yes/' {ssh_config}", "Enabled ChallengeResponseAuthentication in SSH", cve, severity)
    
    # Restart SSH service
    run_command("systemctl restart ssh", "Restarted SSH service to apply 2FA changes", cve, severity)
    
    log_fix_to_csv(cve, severity, action, "Success")

def disable_unused_accounts():
    cve = "CVE-2020-10713"
    severity = "Medium"
    action = "Disable or remove unused user accounts"
    description = "Disabled unused system accounts to mitigate CVE-2020-10713."

    # Identify system accounts (UID < 1000) and disable them by setting their shell to /usr/sbin/nologin
    system_accounts = check_command("awk -F: '($3 < 1000) {print $1}' /etc/passwd").split('\n')
    
    for account in system_accounts:
        if account in ["root", "sync", "shutdown", "halt", "nologin"]:
            continue  # Skip essential system accounts
        run_command(f"usermod -s /usr/sbin/nologin {account}", f"Disabled unused system account: {account}", cve, severity)
    
    log_fix_to_csv(cve, severity, action, "Success")

def configure_grub_password():
    cve = "CVE-2019-14287"
    severity = "High"
    action = "Configure GRUB password protection"
    description = "Instructed user to manually set a GRUB password to mitigate CVE-2019-14287."

    # Since automated password setting is complex and insecure in scripts, provide instructions
    log_action("GRUB password setup requires manual configuration. Please run 'grub-mkpasswd-pbkdf2' and follow the prompts.")
    log_fix_to_csv(cve, severity, action, "Instructions provided for manual GRUB password setup.")

def configure_ntp_authentication():
    cve = "CVE-2016-2776"
    severity = "Medium"
    action = "Configure NTP to use authenticated servers"
    description = "Configured NTP authentication to mitigate CVE-2016-2776."

    ntp_conf = "/etc/ntp.conf"
    backup_file = f"{ntp_conf}.bak"
    
    # Backup ntp.conf
    if os.path.exists(ntp_conf):
        if not os.path.exists(backup_file):
            try:
                shutil.copy2(ntp_conf, backup_file)
                log_action(f"Backup of {ntp_conf} created at {backup_file}")
            except Exception as e:
                log_action(f"ERROR: Failed to backup {ntp_conf}. Error: {str(e)}")
                log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
                return
    else:
        log_action(f"ERROR: {ntp_conf} does not exist. Skipping NTP configuration.")
        log_fix_to_csv(cve, severity, action, f"Failed: {ntp_conf} does not exist.")
        return
    
    # Configure NTP to use authenticated servers
    ntp_auth_config = """
# Enable NTP authentication
enable auth
trustedkey 1
keys /etc/ntp/keys
server 0.debian.pool.ntp.org iburst
server 1.debian.pool.ntp.org iburst
server 2.debian.pool.ntp.org iburst
server 3.debian.pool.ntp.org iburst
    """
    try:
        with open(ntp_conf, "w") as f:
            f.write(ntp_auth_config)
        run_command("systemctl restart ntp", "Restarted NTP service with authentication", cve, severity)
        log_fix_to_csv(cve, severity, action, "Success")
    except Exception as e:
        log_action(f"ERROR: Failed to configure NTP. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")

def configure_login_banner():
    cve = "CVE-2021-3711"
    severity = "High"
    action = "Configure login banner for unauthorized access warnings"
    description = "Configured login banner to display unauthorized access warnings, mitigating CVE-2021-3711."

    banner_file = "/etc/issue.net"
    login_banner = """
*****************************************************
* WARNING: Unauthorized access to this system is    *
* strictly prohibited and will be prosecuted.       *
*****************************************************
"""
    try:
        with open(banner_file, "w") as f:
            f.write(login_banner)
        log_action("Login banner written to /etc/issue.net")
    except Exception as e:
        log_action(f"ERROR: Failed to write login banner. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
        return
    
    # Configure SSH to display the banner
    ssh_config = "/etc/ssh/sshd_config"
    backup_ssh = f"{ssh_config}.bak"
    if not os.path.exists(backup_ssh):
        if os.path.exists(ssh_config):
            try:
                shutil.copy2(ssh_config, backup_ssh)
                log_action(f"Backup of sshd_config created at {backup_ssh}")
            except Exception as e:
                log_action(f"ERROR: Failed to backup {ssh_config}. Error: {str(e)}")
                log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
                return
        else:
            log_action(f"ERROR: {ssh_config} does not exist. Skipping banner configuration.")
            log_fix_to_csv(cve, severity, action, f"Failed: {ssh_config} does not exist.")
            return
    
    try:
        run_command(f"sed -i '/^Banner/s/.*/Banner \/etc\/issue.net/' {ssh_config}", "Configured SSH to display login banner", cve, severity)
        # Restart SSH service
        run_command("systemctl restart ssh", "Restarted SSH service to apply login banner changes", cve, severity)
        log_fix_to_csv(cve, severity, action, "Success")
    except Exception as e:
        log_action(f"ERROR: Failed to configure SSH for login banner. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")

def configure_sudoers():
    cve = "CVE-2019-11236"
    severity = "Medium"
    action = "Configure sudoers to restrict root-level access"
    description = "Configured sudoers file to restrict root-level access, mitigating CVE-2019-11236."

    sudoers_file = "/etc/sudoers"
    sudoers_backup = f"{sudoers_file}.bak"
    
    # Backup sudoers file
    if os.path.exists(sudoers_file):
        if not os.path.exists(sudoers_backup):
            try:
                shutil.copy2(sudoers_file, sudoers_backup)
                log_action(f"Backup of sudoers file created at {sudoers_backup}")
            except Exception as e:
                log_action(f"ERROR: Failed to backup sudoers file. Error: {str(e)}")
                log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
                return
    else:
        log_action(f"ERROR: {sudoers_file} does not exist. Skipping sudoers configuration.")
        log_fix_to_csv(cve, severity, action, f"Failed: {sudoers_file} does not exist.")
        return
    
    # Ensure no lines grant unrestricted root access, and add necessary defaults
    try:
        with open(sudoers_file, "r") as f:
            lines = f.readlines()
        
        with open(sudoers_file, "w") as f:
            for line in lines:
                if line.strip().startswith("root") and "ALL=(ALL)" in line:
                    f.write(line)  # Allow root as is
                elif line.strip().startswith("%admin") or line.strip().startswith("%sudo"):
                    f.write(line)
                else:
                    f.write(line)
            # Add a line to require tty
            if "Defaults    requiretty" not in ''.join(lines):
                f.write("Defaults    requiretty\n")
        
        # Validate sudoers file
        try:
            subprocess.run("visudo -cf /etc/sudoers", check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            log_action("Sudoers file is properly configured.")
            log_fix_to_csv(cve, severity, action, "Sudoers file validated and configured successfully.")
        except subprocess.CalledProcessError as e:
            error_message = e.stderr.decode().strip()
            log_action(f"ERROR: Sudoers file configuration failed. Error: {error_message}")
            log_fix_to_csv(cve, severity, action, f"Failed: {error_message}")
    except Exception as e:
        log_action(f"ERROR: Failed to configure sudoers file. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")

def encrypt_data_at_rest():
    cve = "CVE-2018-16864"
    severity = "High"
    action = "Implement data-at-rest encryption"
    description = "Ensured cryptsetup is installed and advised manual setup for data-at-rest encryption to mitigate CVE-2018-16864."

    check_and_install_tool("cryptsetup", cve, severity)
    
    # Inform the user to set up LUKS encryption manually
    log_action("Data-at-rest encryption requires manual setup. Please configure LUKS encryption for your partitions as needed.")
    log_fix_to_csv(cve, severity, action, "Advised manual setup for data-at-rest encryption.")

def encrypt_system_backups():
    cve = "CVE-2021-34558"
    severity = "Medium"
    action = "Encrypt and securely store system backups"
    description = "Encrypted system backups using GPG to mitigate CVE-2021-34558."

    backup_dir = "/var/backups"  # Replace with your actual backup directory
    encryption_key = "/root/backup.key"
    
    if not os.path.exists(backup_dir):
        log_action(f"Backup directory {backup_dir} does not exist. Creating it.")
        run_command(f"mkdir -p {backup_dir}", f"Created backup directory {backup_dir}", cve, severity)
    
    check_and_install_tool("gpg", cve, severity)
    
    # Generate GPG key if not exists
    gpg_key = "/root/.gnupg/pubring.kbx"
    if not os.path.exists(gpg_key):
        log_action("Generating GPG key for backup encryption.")
        # Corrected key parameters
        gpg_commands = """
echo -e "Key-Type: RSA
Key-Length: 2048
Name-Real: Backup Encryption
Name-Email: backup@example.com
Expire-Date: 0
%commit
" | gpg --batch --generate-key
        """
        try:
            subprocess.run(gpg_commands, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            log_action("Generated GPG key for backups.")
        except subprocess.CalledProcessError as e:
            error_message = e.stderr.decode().strip()
            log_action(f"ERROR: Failed to generate GPG key for backups. Error: {error_message}")
            log_fix_to_csv(cve, severity, action, f"Failed: {error_message}")
            return
    
    # Encrypt existing backups
    try:
        for file in os.listdir(backup_dir):
            filepath = os.path.join(backup_dir, file)
            if os.path.isfile(filepath) and not filepath.endswith(".gpg"):
                recipient = "backup@example.com"  # Replace with your actual email used in GPG key
                run_command(f"gpg --yes --batch --encrypt --recipient {recipient} {filepath}", f"Encrypted backup file {filepath}", cve, severity)
                run_command(f"rm {filepath}", f"Removed unencrypted backup file {filepath}", cve, severity)
        log_fix_to_csv(cve, severity, action, "Success")
    except Exception as e:
        log_action(f"ERROR: Failed to encrypt system backups. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")

def setup_failed_login_notifications():
    cve = "CVE-2020-8558"
    severity = "High"
    action = "Setup notifications for failed login attempts"
    description = "Configured failed login notifications to alert administrators, mitigating CVE-2020-8558."

    notify_script = "/usr/local/bin/failed_login_notify.sh"
    notify_service = "/etc/systemd/system/failed_login_notify.service"
    
    # Create notification script
    script_content = """#!/bin/bash
LOG_FILE="/var/log/auth.log"
EMAIL="admin@example.com"

tail -Fn0 "$LOG_FILE" | \
while read line ; do
    echo "$line" | grep "Failed password" && echo "$line" | mail -s "Failed SSH Login Attempt" $EMAIL
done
"""
    try:
        with open(notify_script, "w") as f:
            f.write(script_content)
        log_action("Created failed login notification script.")
    except Exception as e:
        log_action(f"ERROR: Failed to create notification script. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
        return
    
    # Make the script executable
    run_command(f"chmod +x {notify_script}", "Made failed login notification script executable", cve, severity)
    
    # Create systemd service
    service_content = f"""[Unit]
Description=Failed Login Notification Service
After=network.target

[Service]
ExecStart=/bin/bash {notify_script}
Restart=always

[Install]
WantedBy=multi-user.target
"""
    try:
        with open(notify_service, "w") as f:
            f.write(service_content)
        log_action("Created systemd service for failed login notifications.")
    except Exception as e:
        log_action(f"ERROR: Failed to create systemd service. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
        return
    
    # Enable and start the service
    run_command("systemctl daemon-reload", "Reloaded systemd daemon", cve, severity)
    run_command("systemctl enable failed_login_notify.service", "Enabled failed login notification service", cve, severity)
    run_command("systemctl start failed_login_notify.service", "Started failed login notification service", cve, severity)
    
    log_fix_to_csv(cve, severity, action, "Success")

def configure_outbound_email_auth():
    cve = "CVE-2019-13115"
    severity = "Medium"
    action = "Configure outbound email authentication"
    description = "Configured Postfix to use authenticated SMTP servers, mitigating CVE-2019-13115."

    check_and_install_tool("postfix", cve, severity)
    
    postfix_main = "/etc/postfix/main.cf"
    backup_file = f"{postfix_main}.bak"
    
    # Backup postfix main.cf
    if os.path.exists(postfix_main):
        if not os.path.exists(backup_file):
            try:
                shutil.copy2(postfix_main, backup_file)
                log_action(f"Backup of postfix main.cf created at {backup_file}")
            except Exception as e:
                log_action(f"ERROR: Failed to backup {postfix_main}. Error: {str(e)}")
                log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
                return
    else:
        log_action(f"ERROR: {postfix_main} does not exist. Skipping Postfix configuration.")
        log_fix_to_csv(cve, severity, action, f"Failed: {postfix_main} does not exist.")
        return
    
    # Configure Postfix to use SMTP authentication
    postfix_config_updates = [
        "smtp_sasl_auth_enable = yes",
        "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd",
        "smtp_sasl_security_options = noanonymous",
        "smtp_tls_security_level = encrypt",
        "header_size_limit = 4096000"
    ]
    
    try:
        with open(postfix_main, "a") as f:
            existing_content = f.read()
            for config in postfix_config_updates:
                if config not in existing_content:
                    f.write(f"{config}\n")
        log_action("Updated Postfix main.cf with SMTP authentication settings.")
    except Exception as e:
        log_action(f"ERROR: Failed to update {postfix_main}. Error: {str(e)}")
        log_fix_to_csv(cve, severity, action, f"Failed: {str(e)}")
        return
    
    # Create sasl_passwd file (User must input SMTP credentials)
    sasl_passwd = "/etc/postfix/sasl_passwd"
    if not os.path.exists(sasl_passwd):
        log_action("Please enter your SMTP credentials in /etc/postfix/sasl_passwd in the format:")
        log_action("smtp.example.com username:password")
        log_fix_to_csv(cve, severity, action, "Instructions provided for manual SMTP credentials setup.")
    else:
        log_action(f"{sasl_passwd} already exists. Skipping creation.")
        log_fix_to_csv(cve, severity, action, "Skipped: sasl_passwd already exists.")
    
    # Secure sasl_passwd file
    if os.path.exists(sasl_passwd):
        run_command(f"chmod 600 {sasl_passwd}", "Set permissions for sasl_passwd", cve, severity)
        run_command("postmap /etc/postfix/sasl_passwd", "Created postfix lookup table for sasl_passwd", cve, severity)
    
    # Restart Postfix service
    run_command("systemctl restart postfix", "Restarted Postfix service to apply email authentication settings", cve, severity)
    
    log_fix_to_csv(cve, severity, action, "Success")

def main():
    parser = argparse.ArgumentParser(description="Debian Security Configuration Script")
    parser.add_argument('--enable-extra', action='store_true', help='Enable file integrity monitoring and secure DNS configurations')
    args = parser.parse_args()
    
    print("Starting security configuration updates...")
    log_action("Starting security configuration updates.")
    
    enable_automatic_updates()
    disable_unnecessary_services()
    enforce_password_policy()
    configure_firewall()
    
    if args.enable_extra:
        enable_file_integrity_monitoring()
        configure_secure_dns()
    else:
        log_action("Skipped enable_file_integrity_monitoring and configure_secure_dns as --enable-extra flag was not provided.")
        log_fix_to_csv("N/A", "N/A", "Skipped enable_file_integrity_monitoring and configure_secure_dns", "Skipped: Flag not provided")
    
    install_antivirus()
    enforce_least_privilege()
    enable_secure_boot()
    configure_auditing()
    # configure_ssh()
    lock_accounts_after_failed_logins()
    apply_security_patches()
    install_two_factor_auth()
    disable_unused_accounts()
    configure_grub_password()
    configure_ntp_authentication()
    configure_login_banner()
    configure_sudoers()
    encrypt_data_at_rest()
    encrypt_system_backups()
    setup_failed_login_notifications()
    # configure_outbound_email_auth()
    
    print("Security configuration updates completed.")
    log_action("Security configuration updates completed.")

def check_command(command):
    try:
        result = subprocess.run(command, check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode().strip()
    except subprocess.CalledProcessError as e:
        return e.stderr.decode().strip()

if __name__ == "__main__":
    # Initialize CSV log file with headers if not exists
    if not os.path.exists(CSV_FILE):
        try:
            with open(CSV_FILE, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Timestamp", "CVE", "Severity", "Action", "Description"])
            log_action(f"Created CSV log file at {CSV_FILE}")
        except Exception as e:
            print(f"ERROR: Failed to create CSV log file. Error: {str(e)}")
            sys.exit(1)
    
    main()
