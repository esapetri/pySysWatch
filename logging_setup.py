import logging
import sys
import requests
import inspect
import os
from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler

# Load environment variables from .env file
load_dotenv()

# Slack
SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')

    ## LOGING __________
def setup_logging(log_file='/var/log/system_monitor.log', max_size=10*1024*1024, backup_count=5, disable_slack=False):
    logger = logging.getLogger('system_monitor')
    logger.setLevel(logging.INFO)

    # Create logs directory if it doesn't exist
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(funcName)s() - %(message)s')


    # File handler
    file_handler = RotatingFileHandler(log_file, maxBytes=max_size, backupCount=backup_count)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if not disable_slack:
            # Add the custom handler to the logger
        custom_handler = CustomLogHandler(disable_slack=disable_slack)
        custom_handler.setLevel(logging.ERROR)
        custom_handler.setFormatter(formatter)
        logger.addHandler(custom_handler)

        # Set the custom exception handler as the default
        sys.excepthook = handle_exception

    return logger

def log_error_handler(message, disable_slack=False):
    # Implement additional actions here, like sending notifications or emails
    send_slack_message(
        f"Log Error Handler Activated: {message}",
        SLACK_WEBHOOK_URL,
        logging.getLogger(__name__),
        disable_slack
    )
    print(f"Log Error Handler Activated: {message}")

class CustomLogHandler(logging.Handler):
    def __init__(self, disable_slack=False):
        super().__init__()
        self.disable_slack = disable_slack

    def emit(self, record):
        log_entry = self.format(record)
        log_error_handler(log_entry, self.disable_slack)

def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        # Handle interrupt exceptions differently if necessary
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    logger = logging.getLogger(__name__)
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

def send_slack_message(msg: str, webhook_url: str, logger: logging.Logger, disable_slack: bool = False):
    """
    Sends a message to Slack
    :param msg: The message to send
    :param webhook_url: The Slack webhook URL
    :param logger: The logger instance to use
    :return: None
    """
    #       POST https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
    #       Content-type: application/json
    #       {
    #           "text": "Oh hey, this is a fun message in a channel!",
    #           "response_type": "in_channel"
    #       }
    if disable_slack:
        #logger.info("Slack messaging is disabled.")
        return
    caller_frame = inspect.currentframe().f_back
    func_name = caller_frame.f_code.co_name
    line_no = caller_frame.f_lineno
    file_name = caller_frame.f_code.co_filename
    full_msg = f"[{file_name}:{func_name}:{line_no}] {msg}"
    
    data = {"text": full_msg, "response_type": "in_channel"}
    headers = {"Content-Type": "application/json"}
    try:
        result = requests.post(webhook_url, json=data, headers=headers, timeout=30)
        if 200 <= result.status_code < 300:
            logger.info(f"Webhook sent {result.status_code}")
        else:
            logger.warning(
                f"Not sent with {result.status_code}, response:\n{result.text}"
            )
    except requests.RequestException as e:
        logger.error(f"Error sending Slack message: {str(e)}")

# Initialize logger
#logger = setup_logging()
