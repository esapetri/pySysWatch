import asyncio
import aiofiles
import subprocess
import time
import re
import configparser
import os
from systemd import journal as systemd_journal
import argparse
from integrations.send_email import send_email
from integrations.send_slack import send_slack_message, send_slack_message_async
from logging_setup import setup_logging
from cysystemd.reader import JournalReader, JournalOpenMode
import signal
import sys
from datetime import datetime, timedelta
import psutil
import pytz

# Add this line near the top of the file, after imports
global config

# Add this global variable near the top of the file
cpu_high_load_start_time = None

# Add these global variables near the top of the file
last_disk_usage_report = {}
last_high_memory_report_time = None

def parse_arguments():
    parser = argparse.ArgumentParser(description="System Monitoring Service")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
    parser.add_argument("-c", "--config", default="/etc/system_monitor/config.ini", help="Path to configuration file")
    parser.add_argument("--disable-slack", action="store_true", help="Disable Slack alerts")
    parser.add_argument("-i", "--interval", type=int, default=5, help="Monitoring interval in minutes")
    parser.add_argument("--run-once", action="store_true", help="Run the monitoring once and exit")
    parser.add_argument("--print-to-terminal", action="store_true", help="Print alerts to terminal")
    return parser.parse_args()

def load_config(config_path):
    global config
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    config = configparser.ConfigParser()
    config.read(config_path)
    return config

# Main Daemon Function
async def main(config, interval_minutes, disable_slack, print_to_terminal):
    logger.info("System Monitor Service Started")
    await asyncio.gather(
        monitor_disk_space(config, disable_slack, print_to_terminal),
        monitor_high_cpu_memory(config, disable_slack, print_to_terminal),
        monitor_journal_events(config, interval_minutes, disable_slack, print_to_terminal),
        daily_check_scheduler(config, disable_slack, print_to_terminal)
        #monitor_service_unit_changes(config, disable_slack, print_to_terminal)
    )

# Report to Admin Function
async def report_to_admin(config, subject="NONE", message="error, message missing", disable_slack=False, print_to_terminal=False):
    tasks = []
    if config.getboolean('Alerting', 'EnableEmailAlerts', fallback=False):
        tasks.append(send_email(config, subject, message))
    
    if not disable_slack and config.getboolean('Alerting', 'EnableSlackAlerts', fallback=False):
        slack_webhook_url = config.get('SlackConfig', 'SlackWebhookURL', fallback='').strip("'")
        if slack_webhook_url:
            tasks.append(send_slack_message_async(f"{subject}: {message}", slack_webhook_url))
        else:
            logger.error("Slack webhook URL is not set in the configuration.")
    
    # Execute tasks concurrently
    if tasks:
        await asyncio.gather(*tasks)
    
    if print_to_terminal:
        logger.info(f"ALERT - {subject}: {message}")

# Monitoring Functions
def monitor_disk_space(config, disable_slack, print_to_terminal):
    if not config.getboolean('Monitoring', 'EnableDiskSpaceMonitoring'):
        logger.info("Disk space monitoring is disabled")
        return
    
    global last_disk_usage_report
    current_time = datetime.now()
    
    try:
        logger.debug("Starting disk space monitoring check")
        result = subprocess.run(['df', '-h'], text=True, capture_output=True, check=True)
        lines = result.stdout.splitlines()
        for line in lines[1:]:
            parts = re.split(r'\s+', line)
            usage_percent = int(parts[4].replace('%', ''))
            disk_usage_critical = config.getint('Thresholds', 'DiskUsageCritical', fallback=90)
            disk_usage_warning = config.getint('Thresholds', 'DiskUsageWarning', fallback=80)
            
            if usage_percent >= disk_usage_critical:
                report_level = "Critical"
                logger.critical(f"Critical disk usage detected: {usage_percent}% on {parts[0]}")
            elif usage_percent >= disk_usage_warning:
                report_level = "Warning"
                logger.warning(f"High disk usage detected: {usage_percent}% on {parts[0]}")
            else:
                #logger.debug(f"Normal disk usage: {usage_percent}% on {parts[0]}")
                continue
            
            disk = parts[0]
            if disk not in last_disk_usage_report or current_time - last_disk_usage_report[disk] > timedelta(days=1):
                report_to_admin(config, f"{report_level} Disk Usage Alert", f"Disk usage at {usage_percent}% on {disk}", disable_slack, print_to_terminal)
                last_disk_usage_report[disk] = current_time
                logger.info(f"Sent disk usage alert for {disk}")
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to execute df command: {e.returncode}, {e.output}")
    except ValueError as e:
        logger.error(f"Failed to parse disk usage data: {str(e)}")
    except IndexError as e:
        logger.error(f"Invalid disk usage data format: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during disk monitoring: {str(e)}")

async def monitor_journal_events(config, interval_minutes, disable_slack, print_to_terminal):
    if not config.getboolean('Monitoring', 'EnableJournalMonitoring'):
        return
    keywords = config.get('JournalMonitoring', 'Keywords').split(',')
    event_types = {
        'oom-killer': ('Out of Memory Event Detected', lambda m: 'oom-killer' in m),
        'hardware error': ('Hardware Issue Detected', lambda m: 'hardware error' in m),
        'network': ('Network Issue Detected', lambda m: 'network' in m and 'failed' in m),
        'sudo': ('Sudo Command Executed', lambda m: 'sudo' in m),
        #'service': ('Service Status Change Detected', lambda m: ('failed' in m or 'deactivated' in m) and 'service' in m),
        #'service_deactivation': ('Service Deactivation Detected', lambda m: 'deactivated successfully' in m or 'stopped' in m),
        'login': ('Login Event Detected', lambda m: any([
            'accepted publickey' in m and 'sshd' in m,  # SSH key acceptance
            'accepted password' in m and 'sshd' in m,  # Password login
            'session opened for user' in m and 'pam_unix(sshd:session)' in m,  # PAM session opening
            'new session' in m and 'systemd-logind' in m,  # systemd-logind new session
            'started session' in m and 'systemd' in m and 'user' in m.lower()  # systemd session start
        ])),
        'filesystem error': ('File System Error Detected', lambda m: 'filesystem error' in m),
        'i/o error': ('Disk I/O Error Detected', lambda m: 'i/o error' in m),
        'hardware': ('Hardware Change Detected', lambda m: 'new hardware' in m or 'removed hardware' in m),
        'security alert': ('Security Alert Detected', lambda m: 'security alert' in m),
        'system_state': ('System State Change Detected', lambda m: any([
            'kernel: panic' in m.lower(),  # Kernel panic
            'emergency shutdown' in m.lower(),  # Emergency shutdown
            'system is rebooting' in m.lower(),  # System reboot
            'starting system' in m and 'systemd' in m,  # System startup
            'shutting down system' in m and 'systemd' in m  # System shutdown
        ])),
        'process_error': ('Process Error Detected', lambda m: any([
            'segfault' in m.lower(),  # Segmentation faults
            'process timed out' in m.lower(),  # Process timeouts
            'process killed' in m and 'oom' not in m.lower(),  # Process killed (not OOM)
            'core dumped' in m.lower()  # Core dumps
        ])),
        'security_event': ('Security Event Detected', lambda m: any([
            'permission denied' in m.lower() and 'sshd' not in m,  # Permission denied (not SSH)
            'firewall block' in m.lower(),  # Firewall blocks
            'unattended-upgrade' in m and 'security' in m  # Security updates
            #'authentication failure' in m and 'sudo' not in m  # Auth failures (not sudo)
        ])),
        'critical_service': ('Critical Service Event Detected', lambda m: any([
            'emergency mode' in m.lower(),  # Emergency mode
            'dependency failed' in m and 'systemd' in m,  # Systemd dependency failures
            'failed with result' in m and 'systemd' in m,  # Service failures
            'core service' in m.lower() and 'failed' in m  # Core service issues
        ])),
        'dependency failed': ('Unit Dependency Failure Detected', lambda m: 'dependency failed' in m),
        'time sync': ('Time Synchronization Failure Detected', lambda m: 'time sync' in m and 'failed' in m),
        'power': ('Power Event Detected', lambda m: 'power' in m),
    }
    try:
        journal_reader = JournalReader()
        journal_reader.open(JournalOpenMode.SYSTEM)
        
        # Seek to entries from the last interval
        interval_ago = datetime.now(tz=pytz.UTC) - timedelta(minutes=interval_minutes)
        journal_reader.seek_realtime_usec(int(interval_ago.timestamp() * 1000000))

        for record in journal_reader:
            entry_time = record.data.date.replace(tzinfo=pytz.UTC)
            if entry_time < interval_ago:
                continue
            #print(record.data['MESSAGE'])

            if 'MESSAGE' in record.data:
                message = record.data['MESSAGE'].lower()
                for event_type, (subject, condition) in event_types.items():
                    if condition(message):
                        await report_to_admin(config, subject, message, disable_slack, print_to_terminal)
                        break
    except Exception as e:
        logger.warning(f"Error monitoring journal events: {str(e)}")

def monitor_high_cpu_memory(config, disable_slack, print_to_terminal):
    if not config.getboolean('Monitoring', 'EnableCPUMemoryMonitoring'):
        logger.info("CPU/Memory monitoring is disabled")
        return
    
    global cpu_high_load_start_time, last_high_memory_report_time
    cpu_threshold = 90  # Set threshold to 90%
    duration_threshold = 24 * 60 * 60  # 24 hours in seconds
    
    try:
        logger.debug("Starting CPU/Memory monitoring check")
        # Get CPU usage per core
        cpu_count = psutil.cpu_count()
        cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
        avg_cpu_usage = sum(cpu_percent) / cpu_count
        
        current_time = time.time()
        
        if avg_cpu_usage > cpu_threshold:
            if cpu_high_load_start_time is None:
                cpu_high_load_start_time = current_time
                logger.warning(f"High CPU usage detected: {avg_cpu_usage:.1f}%")
            elif current_time - cpu_high_load_start_time > duration_threshold:
                # Create detailed CPU usage message
                cpu_details = [f"Core {i}: {usage:.1f}%" for i, usage in enumerate(cpu_percent)]
                cpu_info = "\n".join(cpu_details)
                message = (
                    f"Average CPU usage across all cores has been above {cpu_threshold}% "
                    f"for over 24 hours.\nCurrent average: {avg_cpu_usage:.1f}%\n"
                    f"Per-core usage:\n{cpu_info}"
                )
                logger.critical(f"Sustained high CPU usage: {avg_cpu_usage:.1f}% for over 24 hours")
                report_to_admin(config, "Sustained High CPU Usage Alert", message,
                              disable_slack, print_to_terminal)
                # Reset the timer after sending alert
                cpu_high_load_start_time = None
        else:
            if cpu_high_load_start_time is not None:
                logger.info(f"CPU usage returned to normal: {avg_cpu_usage:.1f}%")
            cpu_high_load_start_time = None

        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        total_memory = memory.total + swap.total
        used_memory = memory.used + swap.used
        total_memory_percent = (used_memory / total_memory) * 100
        swap_percent = swap.percent

        memory_threshold = config.getint('Thresholds', 'MemoryUsageThreshold', fallback=90)
        swap_threshold = config.getint('Thresholds', 'SwapUsageThreshold', fallback=85)

        current_datetime = datetime.now()
        if (total_memory_percent >= memory_threshold or swap_percent >= swap_threshold):
            logger.warning(f"High memory usage: Total {total_memory_percent:.2f}%, Swap {swap_percent:.2f}%")
            if (last_high_memory_report_time is None or 
                current_datetime - last_high_memory_report_time > timedelta(hours=1)):
                message = (f"High memory usage detected. Total memory (including swap) usage: "
                         f"{total_memory_percent:.2f}%, Swap usage: {swap_percent:.2f}%")
                report_to_admin(config, "High Memory Usage Alert", message, disable_slack, print_to_terminal)
                last_high_memory_report_time = current_datetime
                logger.info("Sent high memory usage alert")
        else:
            logger.debug(f"Normal memory usage: Total {total_memory_percent:.2f}%, Swap {swap_percent:.2f}%")

    except Exception as e:
        logger.error(f"Error monitoring CPU/memory usage: {str(e)}", exc_info=True)

def monitor_service_unit_changes(config, disable_slack, print_to_terminal):
    if not config.getboolean('Monitoring', 'EnableServiceUnitMonitoring'):
        logger.info("Service unit monitoring is disabled")
        return
    service_unit_path = config.get('ServiceUnitMonitoring', 'ServiceUnitPath')
    if not os.path.isdir(service_unit_path):
        logger.error(f"Service unit directory not found: {service_unit_path}")
        return
    check_interval = config.getint('ServiceUnitMonitoring', 'ServiceUnitCheckInterval')
    
    try:
        logger.info(f"Starting service unit monitoring in {service_unit_path}")
        initial_state = {}
        for filename in os.listdir(service_unit_path):
            if filename.endswith('.service'):
                file_path = os.path.join(service_unit_path, filename)
                initial_state[filename] = os.path.getmtime(file_path)
                logger.debug(f"Tracking service file: {filename}")
        
        while True:
            time.sleep(check_interval)
            logger.debug("Checking for service unit changes")
            for filename in os.listdir(service_unit_path):
                if filename.endswith('.service'):
                    file_path = os.path.join(service_unit_path, filename)
                    current_mtime = os.path.getmtime(file_path)
                    if filename not in initial_state or current_mtime != initial_state[filename]:
                        logger.warning(f"Service unit file change detected: {filename}")
                        report_to_admin(config, "Service Unit File Change Detected", 
                                     f"Change detected in {filename}", disable_slack, print_to_terminal)
                        initial_state[filename] = current_mtime
    except Exception as e:
        logger.error(f"Error monitoring service unit changes: {str(e)}", exc_info=True)

def handle_exit_signal(signum, frame):
    logger.info("Exiting System Monitor Service...")
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, handle_exit_signal)
signal.signal(signal.SIGTERM, handle_exit_signal)

async def check_containers_and_screens(config, disable_slack, print_to_terminal):
    try:
        # Get Docker containers
        docker_output = subprocess.run(['docker', 'ps', '--format', '{{.Names}}\t{{.Status}}'], 
                                     capture_output=True, text=True)
        containers = docker_output.stdout.strip()
        
        # Get Screen sessions
        screen_output = subprocess.run(['screen', '-ls'], 
                                     capture_output=True, text=True)
        screens = screen_output.stdout.strip()
        
        message = "Daily System Status Report\n\n"
        message += "Docker Containers:\n"
        message += containers if containers else "No containers running\n"
        message += "\n\nScreen Sessions:\n"
        message += screens if "There" in screens else "No Screen sessions running\n"
        
        await report_to_admin(config, "Daily Container and Screen Report", message, 
                            disable_slack, print_to_terminal)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error getting container/screen status: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in check_containers_and_screens: {str(e)}")

async def daily_check_scheduler(config, disable_slack, print_to_terminal):
    while True:
        now = datetime.now()
        target_time = now.replace(hour=12, minute=0, second=0, microsecond=0)
        
        # If we've passed today's target time, set for tomorrow
        if now >= target_time:
            target_time += timedelta(days=1)
            
        # Calculate seconds until next check
        wait_seconds = (target_time - now).total_seconds()
        logger.debug(f"Next container/screen check in {wait_seconds/3600:.2f} hours")
        
        await asyncio.sleep(wait_seconds)
        await check_containers_and_screens(config, disable_slack, print_to_terminal)

if __name__ == "__main__":
    args = parse_arguments()
    
    try:
        config = load_config(args.config)
        
        # Setup logging
        logger = setup_logging(
            log_file=config.get('Logging', 'LogFile', fallback='/var/log/system_monitor.log'),
            max_size=config.getint('Logging', 'MaxLogSize', fallback=10*1024*1024),
            backup_count=config.getint('Logging', 'BackupCount', fallback=5),
            disable_slack=args.disable_slack
        )
        
        # Load other configurations
        ADMIN_EMAIL = config.get('EmailConfig', 'AdminEmail', fallback='')
        SMTP_SERVER = config.get('EmailConfig', 'SMTPServer', fallback='localhost')
        SMTP_PORT = config.getint('EmailConfig', 'SMTPPort', fallback=25)
        SMTP_USERNAME = config.get('EmailConfig', 'SMTPUsername', fallback='')
        SMTP_PASSWORD = config.get('EmailConfig', 'SMTPPassword', fallback='')

        DISK_USAGE_WARNING = config.getint('Thresholds', 'DiskUsageWarning', fallback=80)
        DISK_USAGE_CRITICAL = config.getint('Thresholds', 'DiskUsageCritical', fallback=90)
        CPU_USAGE_THRESHOLD = config.getint('Thresholds', 'CPUUsageThreshold', fallback=80)
        MEMORY_USAGE_THRESHOLD = config.getint('Thresholds', 'MemoryUsageThreshold', fallback=80)

        MONITORING_INTERVAL = config.getint('Monitoring', 'MonitoringInterval', fallback=60)

        # Load Slack webhook URL
        slack_webhook_url = config.get('SlackConfig', 'SlackWebhookURL', fallback='').strip("'")
        if not slack_webhook_url and config.getboolean('Alerting', 'EnableSlackAlerts', fallback=False) and not args.disable_slack:
            logger.error("Slack alerts are enabled, but Slack webhook URL is not set in the configuration.")

        # Register signal handlers
        signal.signal(signal.SIGINT, handle_exit_signal)
        signal.signal(signal.SIGTERM, handle_exit_signal)
        
        if args.run_once:
            asyncio.run(main(config, MONITORING_INTERVAL, args.disable_slack, args.print_to_terminal))
        else:
            while True:
                asyncio.run(main(config, MONITORING_INTERVAL, args.disable_slack, args.print_to_terminal))
                time.sleep(args.interval * 60)
                
    except Exception as e:
        logger.error(f"Failed to start monitoring service: {str(e)}")
        exit(1)
