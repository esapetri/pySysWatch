import os
import logging
import inspect
import requests
import socket
from getpass import getuser
from dotenv import load_dotenv
import asyncio
import aiohttp

load_dotenv()

#Slack
#TODO NOT IN USE #SLACK_WEBHOOK_VERIFICATION_SECRET=os.getenv("SLACK_WEBHOOK_VERIFICATION_SECRET")
SLACK_WEBHOOK_URL=os.getenv("SLACK_WEBHOOK_URL")

# FIXME names are oposites than should be this and next
def send_slack_message(msg: str, webhook:str=SLACK_WEBHOOK_URL):
    """
    Sends a message to Slack
    :param msg: The message to send
    :return: None
    """
    caller_frame = inspect.currentframe().f_back
    func_name = caller_frame.f_code.co_name
    line_no = caller_frame.f_lineno
    file_name = caller_frame.f_code.co_filename
    # Get user, hostname, and IP address
    user = getuser()
    hostname = socket.gethostname()
    #ip_address = socket.gethostbyname(hostname)
    
    full_msg = f"[{user}@{hostname}][{file_name}:{func_name}:{line_no}] {msg}"
    
    data = {"text": full_msg, "response_type": "in_channel"}
    headers = {"Content-Type": "application/json"}
    
    try:
        result = requests.post(webhook, json=data, headers=headers, timeout=30)
        result.raise_for_status()
        logging.info(f"Webhook sent successfully with status code {result.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to send webhook: {str(e)}")

async def send_slack_message_async(msg: str, webhook: str):
    """
    Sends a message to Slack asynchronously
    :param msg: The message to send
    :param webhook: The Slack webhook URL
    :return: None
    """
    if not webhook:
        logging.error("Slack webhook URL is not set. Cannot send Slack message.")
        return

    data = {"text": msg, "response_type": "in_channel"}
    headers = {"Content-Type": "application/json"}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook, json=data, headers=headers) as response:
                response.raise_for_status()
                logging.info(f"Slack message sent successfully with status code {response.status}")
    except aiohttp.ClientError as e:
        logging.error(f"Failed to send Slack message: {str(e)}")

def send_plain_slack_message(msg: str, webhook:str=SLACK_WEBHOOK_URL):
    """
    Sends a message to Slack
    :param msg: The message to send
    :return: None
    """    
    full_msg = f"{msg}"
    
    data = {"text": full_msg, "response_type": "in_channel"}
    headers = {"Content-Type": "application/json"}
    
    try:
        result = requests.post(webhook, json=data, headers=headers, timeout=30)
        result.raise_for_status()
        logging.info(f"Webhook sent successfully with status code {result.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to send webhook: {str(e)}")

class SlackHandler(logging.Handler):
    def emit(self, record):
        log_entry = self.format(record)
        caller_frame = inspect.currentframe().f_back
        func_name = caller_frame.f_code.co_name
        line_no = caller_frame.f_lineno
        file_name = caller_frame.f_code.co_filename
        full_msg = f"[{file_name}:{func_name}:{line_no}] {log_entry}"
        send_slack_message(full_msg)

#TODO might need to remove some parts of message as slack message already contains tons
def setup_slack_logging():
    slack_handler = SlackHandler()
    slack_handler.setLevel(logging.WARNING)  # Set to capture WARNING and above
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    slack_handler.setFormatter(formatter)
    logging.getLogger('').addHandler(slack_handler)
