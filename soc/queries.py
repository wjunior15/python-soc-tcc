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
 
def create_db():
    conn = conn_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
            f"""
                DROP TABLE IF EXISTS alerts, captures;

                CREATE TABLE captures(
                    id_pcap SERIAL,
                    ip_src varchar(50) NOT NULL,
                    ip_dst varchar(50) NOT NULL,
                    timestamp_conn bigint NOT NULL,
                    src_port varchar(10),
                    dst_port varchar(10),
                    syn_flag integer NOT NULL,
                    ack_flag integer NOT NULL,
                    win_size decimal(8),
                    cap_status varchar(50),
                    CONSTRAINT PK_pcap PRIMARY KEY (id_pcap)
                );

                CREATE TABLE alerts(
                    id_alert SERIAL,
                    id_pcap integer,
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
                    CONSTRAINT PK_alert PRIMARY KEY (id_alert, id_pcap),
                    CONSTRAINT FK_alert_pcap FOREIGN KEY (id_pcap) REFERENCES captures(id_pcap)
                );
            """)
            conn.commit()
            cursor.close()
            conn_db(conn)
            print(f"Criação do banco executada com sucesso!")
        except Exception as e:
            print(f"Erro ao criar banco:",str(e))
            conn_db(conn)

def insert_pcap_data(in_pcap):
    """Função realiza inserção de pcaps na tabela de captures e retorna o id do item criado.
    
    Args:
        in_pcap (list): lista com valores do trafego de rede
        
    Returns:
        id_pcap (int): id da linha inserida no banco de dados
    """
    conn = conn_db()
    if conn:
        try:
            str_insert = f"""INSERT INTO captures (ip_src, ip_dst, src_port, dst_port, timestamp_conn, syn_flag, ack_flag, win_size, cap_status) VALUES ('{in_pcap[0]}', '{in_pcap[1]}', '{in_pcap[2]}', '{in_pcap[3]}', {np.round(float(in_pcap[4]),8)}, {in_pcap[5]}, {in_pcap[6]}, {np.round(float(in_pcap[7]),8)}, 'NEW') RETURNING id_pcap;"""
            cursor = conn.cursor()
            cursor.execute(str_insert)
            id_pcap = cursor.fetchall()[0][0]
            conn.commit()
            cursor.close()
            conn_db(conn)
            print("Inserção do PCAP",id_pcap,"realizada com sucesso!")
            return id_pcap
        except Exception as e:
            print("Erro ao inserir pcap:",str(e))
            conn_db(conn)

def convert_tuple_to_dt(in_tuple):
    """Função que converte dados retornados de query, em formato de tupla, para datatable

    Args:
        in_tuple (tuple): tupla retornada da query

    Returns:
        out_dt (datatable): datatable montado com dados da tupla
    """
    list_data = []
    for item in in_tuple:
        dict_data = {
                        "ID":item[0],
                        "IP Source":item[1],
                        "IP Destination":item[2],
                        "Source Port":item[4],
                        "Destination Port":item[5],
                        "Timestamp":item[3],
                        "SYN Flag":item[6],
                        "ACK Flag":item[7],
                        "TCP Window Size":item[8]
                    }
        list_data.append(dict_data)
        
    out_dt = pd.DataFrame.from_dict(list_data)
    return out_dt

def get_captures_by_status(in_status):
    """Função que retorna datatable de itens com status solicitado.
    
    Args:
        in_status (string): status buscado.
        
    Returns:
        out_dt (datatable): datatable de itens retornados na busca por status.
    
    """
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
                
            out_dt = convert_tuple_to_dt(tpl_data)
            return out_dt
            
        except Exception as e:
            print("Erro ao extrair dados por status:",str(e))
            conn_db(conn)

def update_status_captures(in_id, in_new_status, in_conn):
    """Função que atualiza o status de um item no banco de acordo com seu id
    
    Args:
        in_id (int): id do item que será atualizado
        in_new_status (string): novo status que será atribuído
        in_conn (psycopg.conn): conexão com banco de dados (caso deseja criar, não passar valor) 
    
    """
    conn = in_conn
    if not in_conn:
        conn =   conn_db()
    
    if conn:
        try:
            str_update = f"""
                UPDATE captures
                SET cap_status = '{in_new_status}'
                WHERE id_pcap = {in_id};
                """
            cursor = conn.cursor()
            cursor.execute(str_update)
            conn.commit()
            cursor.close()
            
            #Encerra conexão criada
            if not in_conn:
                conn_db(conn)
            
            print("Atualização do item",in_id,"realizada com sucesso! Novo Status:", in_new_status)
            
        except Exception as e:
            conn_db(conn)
            print("Erro ao atualizar status do item",in_id,":",str(e))

def insert_alert(in_id, dt_row, in_alert):
    """Função que insere dados de rede de pcap com suspeita de ataque
    
    Args:
        in_id (int): id da captura correspondente ao alerta
        dt_row (datatable.row): linha do datatable que será inserida
        in_alert (string): Tipo de ataque suspeito
        
    Returns:
        id_alert (int): id do alerta criado
    """
    
    id_pcap = in_id
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
                INSERT INTO alerts (id_pcap, label, init_win_fwd, ack_count, fwd_pck, flw_pck, iat_max, iat_min, flw_duration, init_win_bwd, sub_bwd, iat_mean)
                VALUES ({id_pcap}, '{label}', {init_win_fwd}, {ack_count}, {fwd_pck}, {flw_pck}, {iat_max}, {iat_min}, {flw_duration}, {init_win_bwd}, {sub_bwd}, {iat_mean})
                RETURNING id_alert;
                """
    conn = conn_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(insert_query)
            id_alert = cursor.fetchall()[0][0]
            conn.commit()
            cursor.close()
            conn_db(conn)
            print("Inserção do alerta", id_alert,"realizada com sucesso!")
            return id_alert
        
        except Exception as e:
            conn_db(conn)
            print("Erro ao inserir alerta:", str(e))
        
def get_captures_by_ips(in_dst, in_src):
    conn = conn_db()
    if conn:
        try:
            str_query = f"""
                SELECT *
                FROM captures
                WHERE ip_dst IN ('{in_dst}','{in_src}') AND ip_src IN ('{in_dst}','{in_src}');
                """
            cursor = conn.cursor()
            cursor.execute(str_query)
            tpl_data = cursor.fetchall()
            cursor.close()
            conn_db(conn)
                        
            out_dt = convert_tuple_to_dt(tpl_data)
            print("Dados convertidos com sucesso! - Total de linhas do dt:",len(out_dt))
            return out_dt
            
        except Exception as e:
            print("Erro ao extrair dados com lista de atributos:",str(e))
            conn_db(conn)