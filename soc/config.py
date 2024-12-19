import os
import platform

SYSTEM_NAME = platform.system()

if SYSTEM_NAME == 'Windows':
    import dotenv
    dotenv.load_dotenv()
    
PROJECT_PATH = os.getcwd()
PYSHARK_HOST = "soc"

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_DATABASE = os.getenv("DB_DATABASE")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
BOOL_USE_DB = True
INT_DAY_TO_RESET_DB = 1
PYSHARK_CAPTURE_TIMEOUT = 100
PYSHARK_CAPTURE_INTERFACE = 'any'
if SYSTEM_NAME == 'Windows':
    PYSHARK_CAPTURE_INTERFACE = 'WiFi'

BOOL_CLEAR_ALL_DB = True
BOOL_MODEL_CONTAINS_MULTIPLE_LABELS = True
CODE_VERSION='0.3'