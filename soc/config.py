import os
import platform

if platform.system() == 'Windows':
    import dotenv
    dotenv.load_dotenv()
    
PROJECT_PATH = os.getcwd()
PYSHARK_HOST = "app"
DICT_ACTIVE_MODEL_AND_ENCODER = {
                                    1:{"model":"/models/Rede1_15Labels.keras", "encoder":"/encoders/LabelEncoder.joblib"},
                                    2:{"model":"/soc/models/Rede2_2Labels.keras", "encoder":"/soc/encoders/LabelEncoder2.joblib"},
                                    3:{"model":"/soc/models/Rede3_15Labels.keras", "encoder":"/soc/encoders/LabelEncoder3.joblib"},
                                    4:{"model":"/soc/models/Rede4_2Labels.keras", "encoder":"/soc/encoders/LabelEncoder4.joblib"}
                                }
DICT_MAX_VALUES = {
                    'Init_Win_bytes_forward': 65535,
                    'ACK Flag Count': 1,
                    'Fwd Packets/s': 3000000.0,
                    'Flow Packets/s': 4000000.0,
                    'Flow IAT Max': 120000000,
                    'Flow IAT Min': 120000000,
                    'Flow Duration': 119999998,
                    'Init_Win_bytes_backward': 65535,
                    'Subflow Bwd Bytes': 655453030,
                    'Flow IAT Mean': 120000000.0
                    }
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_DATABASE = os.getenv("DB_DATABASE")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
BOOL_USE_DB = True
INT_DAY_TO_RESET_DB = 1
PYSHARK_CAPTURE_TIMEOUT = 100
PYSHARK_CAPTURE_INTERFACE = 'eth0'
DICT_ITEM_NEXT_STATUS = {
                            'NEW':'RUNNING',
                            'RUNNING':'BENIGN'
                        }
BOOL_CLEAR_ALL_DB = True
BOOL_MODEL_CONTAINS_MULTIPLE_LABELS = True
CODE_VERSION='0.1'

#PATH_CSV_PCAP = "output.csv"
#PATH_CSV_MALIGN = "malign_data.csv"
#PATH_CAPTURE_PCAP = "capture.pcap"
#PATH_ACTIVE_MODEL = "models/Rede1_15Labels.keras"
#PATH_ACTIVE_ENCODER = "encoders/LabelEncoder.joblib"