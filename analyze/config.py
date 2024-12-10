import os
import platform

SYSTEM_NAME = platform.system()

if SYSTEM_NAME == 'Windows':
    import dotenv
    dotenv.load_dotenv()
    
PROJECT_PATH = os.getcwd()
MODEL_PATH = "/models/model_portscan.keras"
SCALER_PATH = "/encoders/LabelEncoder.joblib"
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_DATABASE = os.getenv("DB_DATABASE")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
BOOL_USE_DB = True
BOOL_MODEL_CONTAINS_MULTIPLE_LABELS = True
CODE_VERSION='0.3'