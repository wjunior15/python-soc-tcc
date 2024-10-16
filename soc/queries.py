import config
import psycopg2 as psy
import numpy as np
import time
import pandas as pd

def conn_db(conn = None):
    try:
        if not conn:
            out_conn = psy.connect(host = config.DB_HOST,
                            database = config.DB_DATABASE,
                            user = config.DB_USER,
                            password = config.DB_PASSWORD,
                            port = config.DB_PORT)
            #print("Conexão INICIALIZADA com sucesso!")
            return out_conn

        conn.close()
        #print("Conexão ENCERRADA com sucesso!")
    except Exception as e:
        print("Erro ao tratar conexão com banco de dados:",e)
 
def clear_db(in_table, in_int_days):
    timestamp_limit = int(time.time())-int(in_int_days*24*60*60)
    conn = conn_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
            f"""
                DELETE FROM {in_table} WHERE timestamp_conn < {timestamp_limit};
            """)
            conn.commit()
            cursor.close()
            conn_db(conn)
            print(f"Limpeza do banco {in_table} executada com sucesso!")
        except Exception as e:
            print(f"Erro ao limpar banco {in_table}:",str(e))
            conn_db(conn)

def create_db():
    conn = conn_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
            f"""
                DROP TABLE IF EXISTS alerts, captures;

                CREATE TABLE captures(
                    ip_src varchar(50) NOT NULL,
                    ip_dst varchar(50) NOT NULL,
                    timestamp_conn bigint NOT NULL,
                    src_port varchar(10),
                    dst_port varchar(10),
                    syn_flag integer NOT NULL,
                    ack_flag integer NOT NULL,
                    win_size decimal(8),
                    cap_status varchar(50),
                    CONSTRAINT PK_pcap PRIMARY KEY (ip_src, ip_dst, timestamp_conn)
                );

                CREATE TABLE alerts(
                    ip_src varchar(50) NOT NULL,
                    ip_dst varchar(50) NOT NULL,
                    timestamp_conn bigint NOT NULL,
                    label varchar(50) NOT NULL,
                    init_win_fwd integer,
                    ack_count integer,
                    fwd_pck decimal(8),
                    flw_pck decimal(8),
                    iat_max decimal(8),
                    iat_min decimal(8),
                    flw_duration decimal(8),
                    init_win_bwd integer,
                    sub_bwd decimal(8),
                    iat_mean decimal(8),
                    CONSTRAINT PK_alert PRIMARY KEY (ip_src, ip_dst, timestamp_conn, label),
                    CONSTRAINT FK_alert_pcap FOREIGN KEY (ip_src, ip_dst, timestamp_conn) REFERENCES captures(ip_src, ip_dst, timestamp_conn)

                );
            """)
            conn.commit()
            cursor.close()
            conn_db(conn)
            print(f"Criação do banco executada com sucesso!")
        except Exception as e:
            print(f"Erro ao criar banco:",str(e))
            conn_db(conn)

def clear_all_db(in_table):
    conn = conn_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
            f"""
                DELETE FROM {in_table};
            """)
            conn.commit()
            cursor.close()
            conn_db(conn)
            print(f"Limpeza do banco {in_table} executada com sucesso!")
        except Exception as e:
            print(f"Erro ao limpar banco {in_table}:",str(e))
            conn_db(conn)

def insert_pcap_data(in_pcap):
    conn = conn_db()
    if conn:
        try:
            str_insert = f"""INSERT INTO captures (ip_src, ip_dst, src_port, dst_port, timestamp_conn, syn_flag, ack_flag, win_size, cap_status) VALUES ('{in_pcap[0]}', '{in_pcap[1]}', '{in_pcap[2]}', '{in_pcap[3]}', {np.round(float(in_pcap[4]),8)}, {in_pcap[5]}, {in_pcap[6]}, {np.round(float(in_pcap[7]),8)}, 'NEW');"""
            #print("Insert String:",str_insert)
            cursor = conn.cursor()
            cursor.execute(str_insert)
            conn.commit()
            cursor.close()
            conn_db(conn)
            print("Inserção de novo PCAP no banco realizada com sucesso!")
        except Exception as e:
            print("Erro ao inserir pcap:",str(e))
            conn_db(conn)

def convert_tuple_to_dt(in_tuple, in_new_status):
    list_data = []
    for item in in_tuple:
        dict_data = {
                        "IP Source":item[0],
                        "IP Destination":item[1],
                        "Source Port":item[3],
                        "Destination Port":item[4],
                        "Timestamp":item[2],
                        "SYN Flag":item[5],
                        "ACK Flag":item[6],
                        "TCP Window Size":item[7]
                    }
        list_data.append(dict_data)
        
        if in_new_status:
            update_status_captures(item[0], item[1], item[2], in_new_status, None)
        
    out_dt = pd.DataFrame.from_dict(list_data)
    return out_dt

def get_captures_by_status(in_status):
    conn = conn_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
                f"""
                SELECT * FROM captures WHERE cap_status = '{in_status}';
                """)
            tpl_data = cursor.fetchall()
            cursor.close()
            conn_db(conn)
            
            new_status = None
            if in_status in ["NEW","RUNNING"]:
                new_status = config.DICT_ITEM_NEXT_STATUS[in_status]
                
            out_dt = convert_tuple_to_dt(tpl_data, new_status)
            print("Dados convertidos com sucesso! - Total de linhas do dt:",len(out_dt))
            return out_dt
            
        except Exception as e:
            print("Erro ao extrair dados por status:",str(e))
            conn_db(conn)

def update_status_captures(in_ip_src, in_ip_dst, in_timestamp, in_new_status, in_conn):
    conn = in_conn
    if not in_conn:
        conn =   conn_db()
    
    if conn:
        try:
            str_update = f"""
                UPDATE captures
                SET cap_status = '{in_new_status}'
                WHERE ip_src = '{in_ip_src}' AND ip_dst = '{in_ip_dst}' AND timestamp_conn = {in_timestamp};
                """
            #print(str_update)
            cursor = conn.cursor()
            cursor.execute(str_update)
            conn.commit()
            cursor.close()
            if not in_conn:
                conn_db(conn)
            print("Atualização de status realizada com sucesso! Novo Status:", in_new_status)
        except Exception as e:
            conn_db(conn)
            print("Erro ao atualizar status do item:",str(e))

def insert_alert(dt_row, in_alert):
    ip_src = dt_row["Source"]
    ip_dst = dt_row["Destiny"]
    timestamp = dt_row["Timestamp"]
    label = in_alert
    init_win_fwd = dt_row["Init_Win_bytes_forward"]
    ack_count = dt_row["ACK Flag Count"]
    fwd_pck = dt_row["Fwd Packets/s"]
    flw_pck = dt_row["Flow Packets/s"]
    iat_max = dt_row["Flow IAT Max"]
    iat_mean = dt_row["Flow IAT Mean"]
    iat_min = dt_row["Flow IAT Min"]
    flw_duration = dt_row["Flow Duration"]
    if np.isnan(flw_duration):
        flw_duration = 0
    init_win_bwd = dt_row["Init_Win_bytes_backward"]
    sub_bwd = dt_row["Subflow Bwd Bytes"]
    
    insert_query = f"""
                INSERT INTO alerts (ip_src, ip_dst, timestamp_conn, label, init_win_fwd, ack_count, fwd_pck, flw_pck, iat_max, iat_min, flw_duration, init_win_bwd, sub_bwd, iat_mean)
                VALUES ('{ip_src}', '{ip_dst}', {timestamp}, '{label}', {init_win_fwd}, {ack_count}, {fwd_pck}, {flw_pck}, {iat_max}, {iat_min}, {flw_duration}, {init_win_bwd}, {sub_bwd}, {iat_mean})
                """
    conn = conn_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(insert_query)
            conn.commit()
            cursor.close()
            conn_db(conn)
            print("Inserção de Alerta realizada com sucesso!")
        except Exception as e:
            conn_db(conn)
            print("Erro ao inserir alerta:", str(e))

def define_where_string_for_multiple_att(in_name_list, in_value_list, in_condition, in_and_or):
    if len(in_name_list) == len(in_value_list) and len(in_value_list) == len(in_condition):
        list_conditions = []
        for i in range(len(in_name_list)):
            list_conditions.append(f"{in_name_list[i]} {in_condition[i]} {in_value_list[i]}")
        
        out_str_where = f" {in_and_or} ".join(list_conditions)
        #print("Where String:",out_str_where)
        return out_str_where
        
def get_captures_by_attribute_list(in_name_list, in_value_list, in_condition, in_and_or):
    str_where = define_where_string_for_multiple_att(in_name_list, in_value_list, in_condition, in_and_or)
    if str_where:
        conn = conn_db()
        if conn:
            try:
                str_query = f"""
                    SELECT *
                    FROM captures
                    WHERE {str_where};
                    """
                cursor = conn.cursor()
                cursor.execute(str_query)
                tpl_data = cursor.fetchall()
                cursor.close()
                conn_db(conn)
                
                new_status = None                    
                out_dt = convert_tuple_to_dt(tpl_data, new_status)
                print("Dados convertidos com sucesso! - Total de linhas do dt:",len(out_dt))
                return out_dt
                
            except Exception as e:
                print("Erro ao extrair dados com lista de atributos:",str(e))
                conn_db(conn)