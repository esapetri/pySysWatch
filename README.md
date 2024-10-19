# System Monitoring Service

A comprehensive system monitoring service written in Python that tracks various system metrics and sends alerts when thresholds are exceeded.

## Features

- Disk space monitoring
- CPU and memory usage monitoring
- System journal event monitoring
- Service unit file change detection
- Configurable alert thresholds
- Email and Slack notifications

## Prerequisites

- Python 3.7+
- pip (Python package manager)
- systemd (for running as a service)

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/system-monitoring-service.git
   cd system-monitoring-service
   ```

2. **Install the Required Python Packages**
   ```bash
   pip install -r requirements.txt
   ```

3. **Copy the Configuration File**
   ```bash
   sudo mkdir -p /etc/system_monitor
   sudo cp config.ini /etc/system_monitor/config.ini
   ```

4. **Edit the Configuration File**
   ```bash
   sudo nano /etc/system_monitor/config.ini
   ```

## Running the Application

There are several ways to run this monitoring application:

### 1. As a Python Script

Run the script directly using Python:
```bash
python main.py
```

Use command-line arguments for additional options:
- `-v` or `--verbose`: Increase output verbosity
- `-c` or `--config`: Specify a custom config file path

Example:
```bash
python main.py -v -c /path/to/custom/config.ini
```

### 2. As a Systemd Service

1. **Copy the Service File**
   ```bash
   sudo cp system_monitor.service /etc/systemd/system/
   ```

2. **Reload the Systemd Manager**
   ```bash
   sudo systemctl daemon-reload
   ```

3. **Start the Service**
   ```bash
   sudo systemctl start system_monitor
   ```

4. **Enable the Service to Start on Boot**
   ```bash
   sudo systemctl enable system_monitor
   ```

5. **Check the Status of the Service**
   ```bash
   sudo systemctl status system_monitor
   ```

### 3. Using Docker

If you prefer to run the application in a container, you can use Docker:

1. **Build the Docker Image**
   ```bash
   docker build -t system-monitor .
   ```

2. **Run the Container**
   ```bash
   docker run -d --name system-monitor \
     -v /path/to/config.ini:/etc/system_monitor/config.ini \
     -v /var/log:/var/log \
     --privileged \
     system-monitor
   ```

   Note: The `--privileged` flag is required to access system information. Use with caution in production environments.

## Logging

Logs are written to the file specified in the `config.ini` file. By default, this is `/var/log/system_monitor.log`. You can view the logs using:
```bash
tail -f /var/log/system_monitor.log
```

## Troubleshooting

If you encounter any issues:

1. Check the log file for error messages.
2. Verify that the configuration file is correctly set up.
3. Ensure that the script has the necessary permissions to access system information.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Unlicence License - see the LICENSE file for details.

