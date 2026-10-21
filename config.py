# configuration settings for the system security monitor

import os

class Config:
    # application settings
    SECRET_KEY = 'project-secret-key'
    DEBUG = True

    # file paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')

    #create directory if they don't exist
    for dir_path in [DATA_DIR, REPORTS_DIR, LOGS_DIR]:
        os.makedirs(dir_path, exist_ok=True)
    
    # alert storage
    ALERT_FILE = os.path.join(DATA_DIR, 'alerts.json')

    # VirusTotal API
    VIRUSTOTAL_API_KEY ='copy here your API key from virus total website'

    # wind event log settings
    EVENT_LOG_TYPES = ['System', 'Security', 'Application']
    MAX_LOG_ENTRIES = 1000 # max logs to keep in memory

    # detection thresholds
    FAILED_LOGIN_THRESHOLD = 3 # alert after 3 failed logins

    # suspicious processes to monitor
    SUSPICIOUS_PROCESSES = [
        'powershell.exe',
        'cmd.exe',
        'wscript.exe',
        'cscript.exe',
        'rundll32.exe',
        'regsvrs32.exe'
    ]

    # suspicious ports (common backdor)
    SUSPICIOUS_PORTS = [
        4444, # metasploit default
        1337, # various shells
        31337, # back orifice
        5555, # android ADB
        6666, # various
        6667, # IRC (often used by bots)
        6665, # IRC
        6669 # IRC
    ]