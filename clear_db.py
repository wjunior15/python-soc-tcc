import queries
import config

def clear_by_time():
    queries.clear_db("alerts", config.INT_DAY_TO_RESET_DB)
    queries.clear_db("captures", config.INT_DAY_TO_RESET_DB)


def clear_all():
    queries.clear_all_db("alerts")
    queries.clear_all_db("captures")

def invoke_clear(in_clear_all):
    print(" --- Realiza limpeza do banco de dados!")
    if in_clear_all:
        clear_all()
        return 0
    clear_by_time()