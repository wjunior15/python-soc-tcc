import queries
import config

def clear_by_time():
    int_days_reset = config.INT_DAY_TO_RESET_DB
    print("Realiza limpeza do banco - Mantém dados anteriores a",int_days_reset)
    queries.clear_db("alerts", int_days_reset)
    queries.clear_db("captures", int_days_reset)


def clear_all():
    print("Realiza limpeza geral no banco de dados - Inicio de execução")
    queries.clear_all_db("alerts")
    queries.clear_all_db("captures")