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
from integrations.send_slack import send_slack_message
from logging_setup import setup_logging
from cysystemd.reader import JournalReader, JournalOpenMode
import signal
import sys
from datetime import datetime, timedelta
import psutil
import pytz
from typing import Dict, Optional

# Add this line near the top of the file, after imports
global config

# Add this global variable near the top of the file
cpu_high_load_start_time = None

# Add these global variables near the top of the file
last_disk_usage_report = {}
last_high_memory_report_time = None

# Add these global variables
command_monitoring_tasks = {}
last_command_runs = {}

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

def parse_filter_expression(expression):
    """Parse filter expression with AND/OR/NOT operators and quoted strings"""
    def tokenize(expr):
        # Handle quoted strings (both single and double quotes)
        pattern = r'''(?:[^\s"']|"[^"]*"|'[^']*')+'''
        return re.findall(pattern, expr)

    def clean_token(token):
        # Remove quotes from quoted strings
        if (token.startswith('"') and token.endswith('"')) or \
           (token.startswith("'") and token.endswith("'")):
            return token[1:-1].strip().lower()
        return token.strip().lower()

    def create_condition(expr):
        expr = clean_token(expr)
        if expr.startswith('not '):
            inner_expr = clean_token(expr[4:])
            return lambda m: not inner_expr in m.lower()
        return lambda m: expr in m.lower()

    expression = expression.strip()
    if ' or ' in expression:
        tokens = [t for t in tokenize(expression) if t.lower() != 'or']
        conditions = [create_condition(t) for t in tokens]
        return lambda m: any(c(m) for c in conditions)
    elif ' and ' in expression:
        tokens = [t for t in tokenize(expression) if t.lower() != 'and']
        conditions = [create_condition(t) for t in tokens]
        return lambda m: all(c(m) for c in conditions)
    else:
        return create_condition(expression)

def build_event_types(config):
    event_types = {}
    for section in config['JournalMonitoring']:
        if section.endswith('.title'):
            event_name = section[:-6]
            title = config['JournalMonitoring'][section]
            start = config['JournalMonitoring'].get(f'{event_name}.start', '').strip()
            filters_str = config['JournalMonitoring'].get(f'{event_name}.filters', '').strip()

            def create_condition(filters_str, start):
                def condition(message):
                    if start and not message.lower().startswith(start.lower()):
                        return False
                    if not filters_str:  # If no filters, only check start condition
                        return True
                    return parse_filter_expression(filters_str)(message.lower())
                return condition

            event_types[event_name] = (title, create_condition(filters_str, start))
    
    return event_types

# Main Daemon Function
async def async_main(config, interval_minutes, disable_slack, print_to_terminal):
    """Async version of main function"""
    logger.info("System Monitor Service Started")
    
    tasks = [
        monitor_commands(config, disable_slack, print_to_terminal),
        # Convert existing monitoring functions to coroutines or run them in executor
        asyncio.to_thread(monitor_disk_space, config, disable_slack, print_to_terminal),
        asyncio.to_thread(monitor_high_cpu_memory, config, disable_slack, print_to_terminal),
        asyncio.to_thread(monitor_journal_events, config, interval_minutes, disable_slack, print_to_terminal),
        #asyncio.to_thread(monitor_service_unit_changes, config, disable_slack, print_to_terminal),
    ]
    
    await asyncio.gather(*tasks)

def main(config, interval_minutes, disable_slack, print_to_terminal):
    asyncio.run(async_main(config, interval_minutes, disable_slack, print_to_terminal))

# Report to Admin Function
def report_to_admin(config, subject="NONE", message="error, message missing", disable_slack=False, print_to_terminal=False):
    tasks = []
    if config.getboolean('Alerting', 'EnableEmailAlerts', fallback=False):
        tasks.append(send_email(config, subject, message))
    
    if not disable_slack and config.getboolean('Alerting', 'EnableSlackAlerts', fallback=False):
        slack_webhook_url = config.get('SlackConfig', 'SlackWebhookURL', fallback='').strip("'")
        if slack_webhook_url:
            tasks.append(send_slack_message(f"{subject}: {message}", slack_webhook_url))
        else:
            logger.error("Slack webhook URL is not set in the configuration.")
    
    for task in tasks:
        task()
    
    if print_to_terminal:
        print(f"ALERT - {subject}: {message}")

# Monitoring Functions
def monitor_disk_space(config, disable_slack, print_to_terminal):
    if not config.getboolean('Monitoring', 'EnableDiskSpaceMonitoring'):
        return
    
    global last_disk_usage_report
    current_time = datetime.now()
    
    # Get alert frequency from config (in hours), default to 24 hours
    alert_frequency = timedelta(hours=config.getint('Thresholds', 'DiskAlertFrequency', fallback=24))
    
    try:
        result = subprocess.run(['df', '-h'], text=True, capture_output=True, check=True)
        lines = result.stdout.splitlines()
        for line in lines[1:]:
            parts = re.split(r'\s+', line)
            usage_percent = int(parts[4].replace('%', ''))
            disk_usage_critical = config.getint('Thresholds', 'DiskUsageCritical', fallback=90)
            disk_usage_warning = config.getint('Thresholds', 'DiskUsageWarning', fallback=80)
            
            if usage_percent >= disk_usage_critical:
                report_level = "Critical"
            elif usage_percent >= disk_usage_warning:
                report_level = "Warning"
            else:
                continue
            
            disk = parts[0]
            if disk not in last_disk_usage_report or current_time - last_disk_usage_report[disk] > alert_frequency:
                report_to_admin(config, f"{report_level} Disk Usage Alert", f"Disk usage at {usage_percent}% on {disk}", disable_slack, print_to_terminal)
                last_disk_usage_report[disk] = current_time
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Subprocess error: {e.returncode}, {e.output}")
    except ValueError as e:
        logger.error(f"Value error: {str(e)} - Check disk usage parsing logic.")
    except IndexError as e:
        logger.error(f"Index error: {str(e)} - Check line parsing logic.")
    except Exception as e:
        logger.warning(f"Unexpected error: {str(e)}")

def monitor_journal_events(config, interval_minutes, disable_slack, print_to_terminal):
    #https://pypi.org/project/cysystemd/
    if not config.getboolean('Monitoring', 'EnableJournalMonitoring'):
        return

    # Build event types from config using the new logic
    event_types = build_event_types(config)

    try:
        journal_reader = JournalReader()
        journal_reader.open(JournalOpenMode.SYSTEM)
        
        interval_ago = datetime.now(tz=pytz.UTC) - timedelta(minutes=interval_minutes)
        journal_reader.seek_realtime_usec(int(interval_ago.timestamp() * 1000000))

        for record in journal_reader:
            entry_time = record.date.replace(tzinfo=pytz.UTC)
            if entry_time < interval_ago:
                continue

            if 'MESSAGE' in record.data:
                message = record.data['MESSAGE'].lower()
                timestamp = entry_time.strftime("%Y-%m-%d %H:%M:%S %Z")
                
                # Get process identifier (SYSLOG_IDENTIFIER or _COMM as fallback)
                process_name = record.data.get('SYSLOG_IDENTIFIER', 
                             record.data.get('_COMM', 'unknown'))
                
                for event_type, (subject, condition) in event_types.items():
                    if condition(message):
                        formatted_message = f"[{timestamp}] [{process_name}] {message}"
                        report_to_admin(config, subject, formatted_message, disable_slack, print_to_terminal)
                        break
    except Exception as e:
        logger.warning(f"Error monitoring journal events: {str(e)}")

def monitor_high_cpu_memory(config, disable_slack, print_to_terminal):
    if not config.getboolean('Monitoring', 'EnableCPUMemoryMonitoring'):
        return
    
    global cpu_high_load_start_time, last_high_memory_report_time
    
    # Get thresholds and alert frequencies from config
    cpu_threshold = config.getint('Thresholds', 'CPUUsageThreshold', fallback=90)
    cpu_alert_frequency = timedelta(hours=config.getint('Thresholds', 'CPUAlertFrequency', fallback=2))
    memory_threshold = config.getint('Thresholds', 'MemoryUsageThreshold', fallback=90)
    swap_threshold = config.getint('Thresholds', 'SwapUsageThreshold', fallback=85)
    memory_alert_frequency = timedelta(hours=config.getint('Thresholds', 'MemoryAlertFrequency', fallback=1))
    
    try:
        # CPU monitoring
        proc = subprocess.run(
            ['ps', '-eo', 'pid,ppid,cmd,%mem,%cpu', '--sort=-%cpu'],
            capture_output=True, text=True
        )
        lines = proc.stdout.splitlines()
        total_cpu_usage = sum(float(line.split()[-1]) for line in lines[1:])
        
        current_time = datetime.now()
        
        if total_cpu_usage > cpu_threshold:
            if cpu_high_load_start_time is None:
                cpu_high_load_start_time = current_time
            elif current_time - cpu_high_load_start_time > cpu_alert_frequency:
                report_to_admin(
                    config, 
                    "Sustained High CPU Usage Alert", 
                    f"Total CPU usage has been above {cpu_threshold}% for over {cpu_alert_frequency.total_hours()} hours. Current usage: {total_cpu_usage:.2f}%",
                    disable_slack, 
                    print_to_terminal
                )
                cpu_high_load_start_time = current_time  # Reset timer after alert
        else:
            cpu_high_load_start_time = None

        # Memory monitoring
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        total_memory = memory.total + swap.total
        used_memory = memory.used + swap.used
        total_memory_percent = (used_memory / total_memory) * 100
        swap_percent = swap.percent

        if (total_memory_percent >= memory_threshold or swap_percent >= swap_threshold) and \
           (last_high_memory_report_time is None or current_time - last_high_memory_report_time > memory_alert_frequency):
            message = f"High memory usage detected. Total memory (including swap) usage: {total_memory_percent:.2f}%, Swap usage: {swap_percent:.2f}%"
            report_to_admin(config, "High Memory Usage Alert", message, disable_slack, print_to_terminal)
            last_high_memory_report_time = current_time

    except Exception as e:
        logger.error(f"Error monitoring CPU/memory usage: {str(e)}")

#FIXME broken and not in use
def monitor_service_unit_changes(config, disable_slack, print_to_terminal):
    if not config.getboolean('Monitoring', 'EnableServiceUnitMonitoring'):
        return
    service_unit_path = config.get('ServiceUnitMonitoring', 'ServiceUnitPath')
    if not os.path.isdir(service_unit_path):
        logger.error(f"Service unit directory not found: {service_unit_path}")
        return
    check_interval = config.getint('ServiceUnitMonitoring', 'ServiceUnitCheckInterval')
    
    try:
        initial_state = {}
        for filename in os.listdir(service_unit_path):
            if filename.endswith('.service'):
                file_path = os.path.join(service_unit_path, filename)
                initial_state[filename] = os.path.getmtime(file_path)
        
        while True:
            sleep(check_interval)
            for filename in os.listdir(service_unit_path):
                if filename.endswith('.service'):
                    file_path = os.path.join(service_unit_path, filename)
                    current_mtime = os.path.getmtime(file_path)
                    if filename not in initial_state or current_mtime != initial_state[filename]:
                        report_to_admin(config, "Service Unit File Change Detected", f"Change detected in {filename}", disable_slack, print_to_terminal)
                        initial_state[filename] = current_mtime
    except Exception as e:
        logger.error(f"Error monitoring service unit changes: {str(e)}")

def handle_exit_signal(signum, frame):
    logger.info("Exiting System Monitor Service...")
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, handle_exit_signal)
signal.signal(signal.SIGTERM, handle_exit_signal)

# Add this new function
async def monitor_commands(config: Dict, disable_slack: bool, print_to_terminal: bool) -> None:
    """Monitor system commands defined in config."""
    if not config.getboolean('CommandMonitoring', 'EnableCommandMonitoring', fallback=False):
        return

    global command_monitoring_tasks, last_command_runs
    current_time = time.time()

    async def run_command(name: str, cmd_config: Dict) -> None:
        # Check if command exists first
        base_cmd = cmd_config['cmd'].split()[0]
        if not await check_command_exists(base_cmd):
            logger.warning(f"Command '{base_cmd}' not found on system. Monitoring for '{name}' disabled.")
            return

        while True:
            try:
                # Check if it's time to run
                current_time = time.time()
                if name in last_command_runs:
                    time_since_last_run = current_time - last_command_runs[name]
                    if time_since_last_run < int(cmd_config['interval']):
                        await asyncio.sleep(1)
                        continue

                # Run command
                process = await asyncio.create_subprocess_shell(
                    cmd_config['cmd'],
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()

                if process.returncode != 0:
                    logger.warning(f"Command '{name}' failed with return code {process.returncode}")
                    await asyncio.sleep(int(cmd_config['interval']))
                    continue

                output = stdout.decode().strip()

                # Update last run time
                last_command_runs[name] = time.time()

                # Check pattern and format output
                if 'pattern' in cmd_config:
                    match = re.search(cmd_config['pattern'], output)
                    if match:
                        if 'format' in cmd_config:
                            # Use match.group(1) instead of match.groups()
                            message = cmd_config['format'].format(match=[match.group(1)])
                        else:
                            message = f"{name}: {match.group(0)}"

                        # Send alert
                        is_critical = cmd_config.get('critical', 'false').lower() == 'true'
                        await asyncio.to_thread(
                            report_to_admin,
                            config,
                            f"Command Monitor: {name}",
                            message,
                            disable_slack,
                            print_to_terminal
                        )

                await asyncio.sleep(int(cmd_config['interval']))

            except FileNotFoundError:
                logger.warning(f"Command for '{name}' not found. Disabling this monitor.")
                return
            except Exception as e:
                logger.error(f"Command monitoring error - {name}: {str(e)}")
                await asyncio.sleep(60)

    # Parse commands from config
    for key in config['CommandMonitoring']:
        if key.endswith('.cmd'):
            cmd_name = key[:-4]
            cmd_config = {
                'cmd': config['CommandMonitoring'][f'{cmd_name}.cmd'],
                'interval': config['CommandMonitoring'].get(f'{cmd_name}.interval', '300'),
                'pattern': config['CommandMonitoring'].get(f'{cmd_name}.pattern'),
                'format': config['CommandMonitoring'].get(f'{cmd_name}.format'),
                'critical': config['CommandMonitoring'].get(f'{cmd_name}.critical', 'false')
            }
            
            # Create task if not already running
            if cmd_name not in command_monitoring_tasks:
                command_monitoring_tasks[cmd_name] = asyncio.create_task(
                    run_command(cmd_name, cmd_config)
                )

# Add this helper function at the top level
async def check_command_exists(cmd: str) -> bool:
    """Check if a command exists on the system."""
    try:
        # Use 'which' command to check if the command exists
        process = await asyncio.create_subprocess_shell(
            f"which {cmd}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()
        return process.returncode == 0
    except Exception:
        return False

# Update the main execution block
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
            main(config, MONITORING_INTERVAL, args.disable_slack, args.print_to_terminal)
        else:
            while True:
                main(config, MONITORING_INTERVAL, args.disable_slack, args.print_to_terminal)
                time.sleep(args.interval * 60)  # Convert minutes to seconds
        
    except Exception as e:
        logger.error(f"Failed to start monitoring service: {str(e)}")
        exit(1)
