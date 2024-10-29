# pySysWatch System Monitoring Service

A system monitoring service written in Python that tracks various system metrics and sends alerts when thresholds are exceeded.

## Features

- **System Monitoring**
  - Disk space usage and alerts
  - CPU and memory utilization tracking
  - Swap usage monitoring
  - System journal event monitoring
  - Service unit file change detection
  
- **Alert Mechanisms**
  - Email notifications
  - Slack integration
  - Terminal output option
  - Configurable alert thresholds
  - Customizable alert frequencies

- **Journal Event Monitoring**
  - System boot/shutdown events
  - Out of memory incidents
  - Hardware errors
  - Network issues
  - Security events
  - Service failures
  - Login attempts
  - And many more...

- **Command Monitoring**
  - Periodic command execution
  - Pattern matching on command output
  - Configurable execution intervals
  - Critical alert flagging

## Prerequisites

- Python 3.7+
- systemd
- Required system packages:
  ```bash
  # Debian/Ubuntu
  sudo apt install build-essential libsystemd-dev

  # RHEL/CentOS
  sudo dnf install gcc systemd-devel
  ```

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/system-monitoring-service.git
   cd system-monitoring-service
   ```

2. **Set Up Python Environment**
   ```bash
   # Using pipenv (recommended)
   pipenv install

   # Or using pip
   pip install -r requirements.txt
   ```

3. **Configure the Service**
   ```bash
   sudo mkdir -p /etc/system_monitor
   sudo cp config.ini /etc/system_monitor/config.ini
   sudo nano /etc/system_monitor/config.ini
   ```

## Configuration

The `config.ini` file contains all configuration options:

- **Monitoring Settings**
  - Enable/disable specific monitoring features
  - Set thresholds for alerts
  - Configure monitoring intervals

- **Alert Settings**
  - Email configuration (SMTP settings)
  - Slack webhook URL
  - Alert frequencies

- **Journal Monitoring**
  - Customizable event filters
  - Pattern matching rules
  - Event categorization

- **Command Monitoring**
  - Define commands to run
  - Set execution intervals
  - Configure output parsing

## Usage

### Command Line Options

```bash
python main.py [OPTIONS]

Options:
  -v, --verbose           Increase output verbosity
  -c, --config PATH       Path to config file (default: /etc/system_monitor/config.ini)
  --disable-slack         Disable Slack alerts
  -i, --interval MINUTES  Monitoring interval (default: 5)
  --run-once             Run once and exit
  --print-to-terminal    Print alerts to terminal
```

### Running as a Service

1. **Install the Service**
   ```bash
   sudo cp system_monitor.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

2. **Start and Enable**
   ```bash
   sudo systemctl start system_monitor
   sudo systemctl enable system_monitor
   ```

3. **Monitor Status**
   ```bash
   sudo systemctl status system_monitor
   sudo journalctl -u system_monitor -f
   ```

### Docker Support

```bash
# Build
docker build -t system-monitor .

# Run
docker run -d \
  --name system-monitor \
  -v /path/to/config.ini:/etc/system_monitor/config.ini \
  -v /var/log:/var/log \
  --privileged \
  system-monitor
```

## Logging

- Default log location: `/var/log/system_monitor.log`
- Configurable log rotation
- Supports different log levels (DEBUG, INFO, WARNING, ERROR)

```bash
# View logs
tail -f /var/log/system_monitor.log

# View service logs
journalctl -u system_monitor -f
```

## Troubleshooting

1. **Permission Issues**
   - Ensure proper permissions for log directory
   - Check systemd service user permissions

2. **Configuration Problems**
   - Validate config.ini syntax
   - Check log file for configuration errors

3. **Missing Dependencies**
   - Verify all system packages are installed
   - Check Python package installation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is released into the public domain under the Unlicense - see the [LICENSE](LICENSE) file for details.

