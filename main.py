import asyncio
import aiofiles
import subprocess
import time
import re
import configparser
import logging
import os
from systemd import journal
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import argparse
from integrations.send_email import send_email
from integrations.send_slack import send_slack_message

def parse_arguments():
    parser = argparse.ArgumentParser(description="System Monitoring Service")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
    parser.add_argument("-c", "--config", default="/etc/system_monitor/config.ini", help="Path to configuration file")
    return parser.parse_args()

def setup_logging(verbose):
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(config_path):
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    config = configparser.ConfigParser()
    config.read(config_path)
    return config

# Load configuration
config = load_config('/etc/system_monitor/config.ini')

# Setup logging
LOG_FILE = config.get('General', 'LogFile')
LOG_LEVEL = getattr(logging, config.get('General', 'LogLevel', fallback='INFO'))
logging.basicConfig(filename=LOG_FILE, level=LOG_LEVEL, format='%(asctime)s %(levelname)s: %(message)s')

# Load other configurations
ADMIN_EMAIL = config.get('Alerting', 'AdminEmail')
SMTP_SERVER = config.get('Alerting', 'SMTPServer')
SMTP_PORT = config.getint('Alerting', 'SMTPPort')
SMTP_USERNAME = config.get('Alerting', 'SMTPUsername')
SMTP_PASSWORD = config.get('Alerting', 'SMTPPassword')

DISK_USAGE_WARNING = config.getint('Thresholds', 'DiskUsageWarning')
DISK_USAGE_CRITICAL = config.getint('Thresholds', 'DiskUsageCritical')
CPU_USAGE_THRESHOLD = config.getint('Thresholds', 'CPUUsageThreshold')
MEMORY_USAGE_THRESHOLD = config.getint('Thresholds', 'MemoryUsageThreshold')

MONITORING_INTERVAL = config.getint('Monitoring', 'MonitoringInterval')

# Report to Admin Function
async def report_to_admin(config, subject, message):
    if config.getboolean('Alerting', 'EnableEmailAlerts'):
        await send_email(config, subject, message)
    
    if config.getboolean('Alerting', 'EnableSlackAlerts'):
        slack_webhook_url = config.get('SlackConfig', 'SlackWebhookURL')
        await send_slack_message(f"{subject}: {message}", slack_webhook_url)

# Monitoring Functions
async def monitor_disk_space(config):
    if not config.getboolean('Monitoring', 'EnableDiskSpaceMonitoring'):
        return
    try:
        proc = await asyncio.create_subprocess_exec(
            'df', '-h', stdout=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode().splitlines()
        for line in lines[1:]:
            parts = re.split(r'\s+', line)
            usage_percent = int(parts[4].replace('%', ''))
            if usage_percent >= config.getint('Thresholds', 'DiskUsageCritical'):
                await report_to_admin(config, "Critical Disk Usage Alert", f"Disk usage at {usage_percent}% on {parts[0]}")
            elif usage_percent >= config.getint('Thresholds', 'DiskUsageWarning'):
                await report_to_admin(config, "Warning Disk Usage Alert", f"Disk usage at {usage_percent}% on {parts[0]}")
    except Exception as e:
        logging.error(f"Error monitoring disk space: {str(e)}")

async def monitor_journal_events(config):
    if not config.getboolean('Monitoring', 'EnableJournalMonitoring'):
        return
    keywords = config.get('JournalMonitoring', 'Keywords').split(',')
    event_types = {
        'reboot': ('System Reboot/Shutdown Detected', lambda m: any(kw in m for kw in keywords)),
        'oom-killer': ('Out of Memory Event Detected', lambda m: 'oom-killer' in m),
        'hardware error': ('Hardware Issue Detected', lambda m: 'hardware error' in m),
        'network': ('Network Issue Detected', lambda m: 'network' in m and 'failed' in m),
        'sudo': ('Sudo Command Executed', lambda m: 'sudo' in m),
        'service': ('Service Failure Detected', lambda m: 'failed' in m and 'service' in m),
        'login': ('Login Event Detected', lambda m: 'login' in m),
        'filesystem error': ('File System Error Detected', lambda m: 'filesystem error' in m),
        'i/o error': ('Disk I/O Error Detected', lambda m: 'i/o error' in m),
        'hardware': ('Hardware Change Detected', lambda m: 'new hardware' in m or 'removed hardware' in m),
        'security alert': ('Security Alert Detected', lambda m: 'security alert' in m),
        'dependency failed': ('Unit Dependency Failure Detected', lambda m: 'dependency failed' in m),
        'time sync': ('Time Synchronization Failure Detected', lambda m: 'time sync' in m and 'failed' in m),
        'power': ('Power Event Detected', lambda m: 'power' in m),
    }
    try:
        j = journal.Reader()
        j.log_level(journal.LOG_INFO)
        j.seek_tail()
        j.get_previous()
        j.seek_tail()

        while True:
            j.wait(1000)
            for entry in j:
                if 'MESSAGE' in entry:
                    message = entry['MESSAGE'].lower()
                    for event_type, (subject, condition) in event_types.items():
                        if condition(message):
                            await report_to_admin(config, subject, message)
                            break
    except Exception as e:
        logging.error(f"Error monitoring journal events: {str(e)}")

async def monitor_high_cpu_memory(config):
    if not config.getboolean('Monitoring', 'EnableCPUMemoryMonitoring'):
        return
    try:
        proc = await asyncio.create_subprocess_exec(
            'ps', '-eo', 'pid,ppid,cmd,%mem,%cpu', '--sort=-%cpu',
            stdout=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode().splitlines()
        for line in lines[1:5]:  # Check top 5 CPU consumers
            parts = re.split(r'\s+', line)
            cpu_usage = float(parts[-1])
            if cpu_usage > config.getfloat('Thresholds', 'CPUUsageThreshold'):
                await report_to_admin(config, "High CPU Usage Alert", f"Process {parts[2]} is using {cpu_usage}% CPU")
    except Exception as e:
        logging.error(f"Error monitoring CPU/memory usage: {str(e)}")

async def monitor_service_unit_changes(config):
    if not config.getboolean('Monitoring', 'EnableServiceUnitMonitoring'):
        return
    service_unit_path = config.get('ServiceUnitMonitoring', 'ServiceUnitPath')
    check_interval = config.getint('ServiceUnitMonitoring', 'ServiceUnitCheckInterval')
    try:
        async with aiofiles.open(service_unit_path, mode='r') as file:
            initial_content = await file.read()
        
        while True:
            await asyncio.sleep(check_interval)  # Check every minute
            async with aiofiles.open(service_unit_path, mode='r') as file:
                current_content = await file.read()
            
            if current_content != initial_content:
                await report_to_admin(config, "Service Unit File Change Detected", "A change in service unit files has been detected.")
                initial_content = current_content
    except Exception as e:
        logging.error(f"Error monitoring service unit changes: {str(e)}")

# Main Daemon Function
async def main(config):
    logging.info("System Monitor Service Started")
    monitoring_tasks = [
        monitor_disk_space(config),
        monitor_high_cpu_memory(config),
        monitor_journal_events(config),
        monitor_service_unit_changes(config)
    ]
    await asyncio.gather(*monitoring_tasks)

if __name__ == "__main__":
    args = parse_arguments()
    setup_logging(args.verbose)
    
    try:
        config = load_config(args.config)
        
        # Fork the process (daemon creation code remains the same)
        try:
            pid = os.fork()
            if pid > 0:
                exit(0)  # Parent process exits
        except OSError as e:
            logging.error(f"Fork failed: {e.errno} ({e.strerror})")
            exit(1)

        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                exit(0)  # Second parent exits
        except OSError as e:
            logging.error(f"Fork failed: {e.errno} ({e.strerror})")
            exit(1)

        # Start monitoring
        asyncio.run(main(config))
    except Exception as e:
        logging.error(f"Failed to start monitoring service: {str(e)}")
        exit(1)
