import os
from dotenv import load_dotenv

load_dotenv()

# Network interface to monitor
INTERFACE = "eth0"

# Alert thresholds
PORT_SCAN_THRESHOLD = 10  # ports hit in 60 seconds
BRUTE_FORCE_THRESHOLD = 5  # failed attempts in 60 seconds

# Known devices (MAC addresses) - add your devices here
KNOWN_DEVICES = {
    # "aa:bb:cc:dd:ee:ff": "Device Name",
}

# Slack webhook (optional)
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK", "")

# Database
DB_PATH = "ids.db"
