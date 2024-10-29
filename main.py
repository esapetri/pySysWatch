# Standard library imports
import argparse
import asyncio
import os
import re
import signal
import subprocess
import sys
import time
import configparser
from datetime import datetime, timedelta
from typing import Dict, Optional

# Third-party imports
import aiofiles
import psutil
import pytz
from cysystemd.reader import JournalReader, JournalOpenMode
#https://github.com/mosquito/cysystemd
#https://pypi.org/project/cysystemd/
from systemd import journal as systemd_journal
from sympy.parsing.sympy_parser import parse_expr
from sympy import Symbol

# Local imports
from integrations.send_email import send_email
from integrations.send_slack import send_slack_message
from logging_setup import setup_logging

# Add this line near the top of the file, after imports
global config

cpu_high_load_start_time = None
last_disk_usage_report = {}
last_high_memory_report_time = None
command_monitoring_tasks = {}
last_command_runs = {}
logger = None

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

def evaluate_filter_with_sympy(filter_str: str, event_text: str, debug: bool = False, matches: dict = None) -> bool:
    """
    Evaluate a logical filter string against event text using sympy.
    Shows which parts of the filter matched.
    """
    try:
        # Create a valid symbol name for each term
        terms_map = {}
        counter = 0
        
        # First, preserve quoted strings
        parts = filter_str.split('"')
        processed_terms = []
        
        for i, part in enumerate(parts):
            if i % 2 == 0:  # Outside quotes
                processed_terms.append(part)
            else:  # Inside quotes
                symbol_name = f"term_{counter}"
                terms_map[symbol_name] = part
                processed_terms.append(symbol_name)
                counter += 1
        
        # Rejoin and convert operators
        filter_str = ''.join(processed_terms)
        filter_str = (filter_str.replace(' and ', ' & ')
                               .replace(' or ', ' | ')
                               .replace('not ', '~')
                               .replace('(', ' ( ')
                               .replace(')', ' ) ')
                               .strip())
        
        # Handle 'not(' case specifically
        filter_str = filter_str.replace('~(', '~ (')
        
        # Ensure proper spacing around operators
        filter_str = ' '.join(token for token in filter_str.split() if token)
        
        # Add parentheses if needed
        if '|' in filter_str and '&' in filter_str and not filter_str.startswith('('):
            filter_str = f"({filter_str})"
        
        # Create symbols and truth values
        event_text = event_text.lower()
        symbols = {}
        truth_values = {}
        match_results = {}
        
        # Handle terms from the mapping
        for symbol_name, term in terms_map.items():
            symbols[symbol_name] = Symbol(symbol_name)
            is_match = term.lower() in event_text
            truth_values[symbols[symbol_name]] = is_match
            match_results[term] = is_match
        
        if matches is not None:
            matches.clear()
            matches.update(match_results)

        expr = parse_expr(filter_str, evaluate=False)
        return bool(expr.subs(truth_values))
        
    except Exception as e:
        if debug:
            print(f"Error parsing filter '{filter_str}': {e}")
            print(f"Event text: {event_text}")
        return False

async def monitor_commands(config: Dict, disable_slack: bool, print_to_terminal: bool) -> None:
    logger.debug("Starting command monitoring")
    if not config.getboolean('CommandMonitoring', 'EnableCommandMonitoring', fallback=False):
        logger.debug("Command monitoring disabled in config")
        return

    async def run_command(name: str, cmd_config: Dict) -> None:
        logger.debug(f"Setting up monitoring for command: {name}")
        logger.debug(f"Command config: {cmd_config}")
        
        base_cmd = cmd_config['cmd'].split()[0]
        if not await check_command_exists(base_cmd):
            logger.warning(f"Command '{base_cmd}' not found on system. Monitoring for '{name}' disabled.")
            return

        while True:
            try:
                current_time = time.time()
                if name in last_command_runs:
                    time_since_last_run = current_time - last_command_runs[name]
                    logger.debug(f"Time since last run for {name}: {time_since_last_run}s")
                    if time_since_last_run < int(cmd_config['interval']):
                        await asyncio.sleep(1)
                        continue

                logger.debug(f"Executing command: {cmd_config['cmd']}")
                process = await asyncio.create_subprocess_shell(
                    cmd_config['cmd'],
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if stderr:
                    logger.debug(f"Command stderr: {stderr.decode().strip()}")
                
                if process.returncode != 0:
                    logger.warning(f"Command '{name}' failed with return code {process.returncode}")
                    logger.debug(f"Command output: {stdout.decode().strip()}")
                    await asyncio.sleep(int(cmd_config['interval']))
                    continue

                output = stdout.decode().strip()
                logger.debug(f"Command output: {output}")

                if 'pattern' in cmd_config:
                    logger.debug(f"Checking pattern: {cmd_config['pattern']}")
                    match = re.search(cmd_config['pattern'], output)
                    if match:
                        logger.debug(f"Pattern matched: {match.group(0)}")
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
                logger.error(f"Command monitoring error - {name}: {str(e)}", exc_info=True)
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

def report_to_admin(config, subject="NONE", message="error, message missing", disable_slack=False, print_to_terminal=False):
    """Send alerts through configured channels"""
    logger.debug(f"Sending alert - Subject: {subject}")
    
    try:
        if config.getboolean('Alerting', 'EnableEmailAlerts', fallback=False):
            logger.debug("Sending email alert")
            send_email(config, subject, message)
        
        if not disable_slack and config.getboolean('Alerting', 'EnableSlackAlerts', fallback=False):
            slack_webhook_url = config.get('SlackConfig', 'SlackWebhookURL', fallback='')
            if slack_webhook_url:
                logger.debug("Sending Slack alert")
                send_slack_message(f"{subject}: {message}", slack_webhook_url)
            else:
                logger.error("Slack webhook URL is not set in the configuration")
        
        if print_to_terminal:
            logger.debug("Printing alert to terminal")
            print(f"ALERT - {subject}: {message}")
            
    except Exception as e:
        logger.error(f"Error in report_to_admin: {str(e)}", exc_info=True)

def monitor_disk_space(config, disable_slack, print_to_terminal):
    """Monitor disk space usage"""
    logger.debug("Starting disk space monitoring")
    if not config.getboolean('Monitoring', 'EnableDiskSpaceMonitoring'):
        logger.debug("Disk space monitoring disabled in config")
        return
    
    global last_disk_usage_report
    current_time = datetime.now()
    
    alert_frequency = timedelta(hours=config.getint('Thresholds', 'DiskAlertFrequency', fallback=24))
    logger.debug(f"Alert frequency set to {alert_frequency} hours")
    
    try:
        result = subprocess.run(['df', '-h'], text=True, capture_output=True, check=True)
        lines = result.stdout.splitlines()
        for line in lines[1:]:
            parts = re.split(r'\s+', line)
            usage_percent = int(parts[4].replace('%', ''))
            disk_usage_critical = config.getint('Thresholds', 'DiskUsageCritical', fallback=90)
            disk_usage_warning = config.getint('Thresholds', 'DiskUsageWarning', fallback=80)
            
            logger.debug(f"Disk: {parts[0]}, Usage: {usage_percent}%, Critical: {disk_usage_critical}%, Warning: {disk_usage_warning}%")
            
            if usage_percent >= disk_usage_critical:
                report_level = "Critical"
            elif usage_percent >= disk_usage_warning:
                report_level = "Warning"
            else:
                logger.debug(f"Disk {parts[0]} usage ({usage_percent}%) below warning threshold")
                continue
            
            disk = parts[0]
            if disk not in last_disk_usage_report:
                logger.debug(f"First alert for disk {disk}")
            elif current_time - last_disk_usage_report[disk] <= alert_frequency:
                logger.debug(f"Skipping alert for disk {disk} - within alert frequency period")
                continue
                
            logger.debug(f"Sending {report_level} alert for disk {disk}")
            report_to_admin(config, f"{report_level} Disk Usage Alert", 
                          f"Disk usage at {usage_percent}% on {disk}", 
                          disable_slack, print_to_terminal)
            last_disk_usage_report[disk] = current_time
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Subprocess error: {e.returncode}, {e.output}")
    except ValueError as e:
        logger.error(f"Value error: {str(e)} - Check disk usage parsing logic.")
    except IndexError as e:
        logger.error(f"Index error: {str(e)} - Check line parsing logic.")
    except Exception as e:
        logger.warning(f"Unexpected error: {str(e)}")

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

# Move monitor_journal_events function definition before async_main
def monitor_journal_events(config, interval_minutes, disable_slack, print_to_terminal):
    logger.debug("Starting journal event monitoring")
    if not config.getboolean('Monitoring', 'EnableJournalMonitoring'):
        logger.debug("Journal monitoring disabled in config")
        return

    # Load filters from config
    filters = {
        key.replace('.filters', ''): {
            'title': config['JournalMonitoring'].get(f'{key.replace(".filters", "")}.title', key),
            'filter': config['JournalMonitoring'][key]
        }
        for key in config['JournalMonitoring']
        if key.endswith('.filters')
    }
    
    logger.debug(f"Loaded filters: {list(filters.keys())}")

    try:
        journal_reader = JournalReader()
        journal_reader.open(JournalOpenMode.SYSTEM)
        
        interval_ago = datetime.now(tz=pytz.UTC) - timedelta(minutes=interval_minutes)
        cutoff_usec = int(interval_ago.timestamp() * 1_000_000)
        journal_reader.seek_realtime_usec(cutoff_usec)
        
        for record in journal_reader:
            entry_usec = record.get_realtime_usec()
            if entry_usec < cutoff_usec:
                continue

            if 'MESSAGE' in record.data:
                message = record.data['MESSAGE']
                timestamp = datetime.fromtimestamp(entry_usec / 1_000_000).strftime("%Y-%m-%d %H:%M:%S %Z")
                process_name = record.data.get('SYSLOG_IDENTIFIER', record.data.get('_COMM', 'unknown'))
                
                # Test message against each filter
                for event_name, filter_data in filters.items():
                    matches = {}
                    if evaluate_filter_with_sympy(filter_data['filter'], message, matches=matches):
                        formatted_message = f"[{timestamp}] [{process_name}] {message}"
                        report_to_admin(
                            config,
                            f"Journal Event: {filter_data['title']}", 
                            formatted_message,
                            disable_slack,
                            print_to_terminal
                        )
                        break

    except Exception as e:
        logger.error(f"Error monitoring journal events: {str(e)}", exc_info=True)

# Then define async_main
async def async_main(config, interval_minutes, disable_slack, print_to_terminal):
    """Async version of main function"""
    logger.info("System Monitor Service Started")
    
    try:
        # Create tasks for async functions
        command_monitor_task = asyncio.create_task(monitor_commands(config, disable_slack, print_to_terminal))
        
        # Create tasks for sync functions using to_thread
        disk_space_task = asyncio.create_task(
            asyncio.to_thread(monitor_disk_space, config, disable_slack, print_to_terminal)
        )
        cpu_memory_task = asyncio.create_task(
            asyncio.to_thread(monitor_high_cpu_memory, config, disable_slack, print_to_terminal)
        )
        journal_task = asyncio.create_task(
            asyncio.to_thread(monitor_journal_events, config, interval_minutes, disable_slack, print_to_terminal)
        )
        
        # Gather all tasks
        await asyncio.gather(
            command_monitor_task,
            disk_space_task,
            cpu_memory_task,
            journal_task
        )
    except Exception as e:
        logger.error(f"Error in async_main: {str(e)}", exc_info=True)

def main(config, interval_minutes, disable_slack, print_to_terminal):
    try:
        asyncio.run(async_main(config, interval_minutes, disable_slack, print_to_terminal))
    except Exception as e:
        logger.error(f"Error in main: {str(e)}", exc_info=True)

def handle_exit_signal(signum, frame):
    logger.info("Exiting System Monitor Service...")
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, handle_exit_signal)
signal.signal(signal.SIGTERM, handle_exit_signal)

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

def setup_monitoring(config_path: str, disable_slack: bool = False):
    """Initialize logger and config globally"""
    global logger, config
    config = load_config(config_path)
    
    logger = setup_logging(
        log_file=config.get('Logging', 'LogFile', fallback='./logs/system_monitor.log'),
        max_size=config.getint('Logging', 'MaxLogSize', fallback=10*1024*1024),
        backup_count=config.getint('Logging', 'BackupCount', fallback=5),
        disable_slack=disable_slack
    )
    return config, logger

# Update the main execution block:
if __name__ == "__main__":
    args = parse_arguments()
    
    try:
        config, logger = setup_monitoring(args.config, args.disable_slack)
        
        if args.run_once:
            main(config, args.interval, args.disable_slack, args.print_to_terminal)
        else:
            while True:
                main(config, args.interval, args.disable_slack, args.print_to_terminal)
                time.sleep(args.interval * 60)
                
    except Exception as e:
        if logger:
            logger.error(f"Failed to start monitoring service: {str(e)}")
        else:
            print(f"Failed to start monitoring service: {str(e)}")
        exit(1)

def monitor_journal_events(config, interval_minutes, disable_slack, print_to_terminal):
    logger.debug("Starting journal event monitoring")
    if not config.getboolean('Monitoring', 'EnableJournalMonitoring'):
        logger.debug("Journal monitoring disabled in config")
        return

    # Load filters from config
    filters = {
        key.replace('.filters', ''): {
            'title': config['JournalMonitoring'].get(f'{key.replace(".filters", "")}.title', key),
            'filter': config['JournalMonitoring'][key]
        }
        for key in config['JournalMonitoring']
        if key.endswith('.filters')
    }
    
    logger.debug(f"Loaded filters: {list(filters.keys())}")

    try:
        journal_reader = JournalReader()
        journal_reader.open(JournalOpenMode.SYSTEM)
        
        interval_ago = datetime.now(tz=pytz.UTC) - timedelta(minutes=interval_minutes)
        cutoff_usec = int(interval_ago.timestamp() * 1_000_000)
        journal_reader.seek_realtime_usec(cutoff_usec)
        
        for record in journal_reader:
            entry_usec = record.get_realtime_usec()
            if entry_usec < cutoff_usec:
                continue

            if 'MESSAGE' in record.data:
                message = record.data['MESSAGE']
                timestamp = datetime.fromtimestamp(entry_usec / 1_000_000).strftime("%Y-%m-%d %H:%M:%S %Z")
                process_name = record.data.get('SYSLOG_IDENTIFIER', record.data.get('_COMM', 'unknown'))
                
                # Test message against each filter
                for event_name, filter_data in filters.items():
                    matches = {}
                    if evaluate_filter_with_sympy(filter_data['filter'], message, matches=matches):
                        formatted_message = f"[{timestamp}] [{process_name}] {message}"
                        report_to_admin(
                            config,
                            f"Journal Event: {filter_data['title']}", 
                            formatted_message,
                            disable_slack,
                            print_to_terminal
                        )
                        break

    except Exception as e:
        logger.error(f"Error monitoring journal events: {str(e)}", exc_info=True)
