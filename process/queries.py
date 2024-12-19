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

def convert_tuple_to_dict(in_tuple):
    """Função que converte dados retornados de query, em formato de tupla, para datatable

    Args:
        in_tuple (tuple): tupla retornada da query

    Returns:
        out_dt (dict): dict montado com dados da tupla
    """
    out_dict = None
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
                        "TCP Window Size":item[8],
                        "Label":item[9]
                    }
        
        return dict_data
        
    return out_dict

def update_status_captures(in_id, in_new_status):
    """Função que atualiza o status de um item no banco de acordo com seu id
    
    Args:
        in_id (int): id do item que será atualizado
        in_new_status (string): novo status que será atribuído    
    """
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
    mean_win_fwd = dt_row["Mean Win Fwd"]
    ack_count = dt_row["ACK Flag Count"]
    syn_count = dt_row["SYN Flag Count"]
    fwd_pck = dt_row["Fwd Packets/s"]
    bwd_pck = dt_row["Bwd Packets/s"]
    iat_max = dt_row["Flow IAT Max"]
    iat_mean = dt_row["Flow IAT Mean"]
    iat_min = dt_row["Flow IAT Min"]
    mean_win_bwd = dt_row["Mean Win Bwd"]
    ports_number = dt_row["Ports Number"]
    
    insert_query = f"""
                INSERT INTO alerts (id_pcap, label, mean_win_fwd, ack_count, syn_count, fwd_pck, bwd_pck, iat_max, iat_min, mean_win_bwd, ports_number, iat_mean, status)
                VALUES ({id_pcap}, '{label}', {mean_win_fwd}, {ack_count}, {syn_count}, {fwd_pck}, {bwd_pck}, {iat_max}, {iat_min}, {mean_win_bwd}, {ports_number}, {iat_mean}, 'NEW')
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
    """Função que busca por capturas de trafego entre dois ips
    
    Args:
        in_dst (string): ip da máquina dada como destino da conexão
        in_src (string): ip da máquina dada como fonte da conexão
    
    Returns:
        out_dt (datatable): dados de todas as conexões correspondentes neste fluxo
    
    """
    conn = conn_db()
    if conn:
        try:
            str_query = f"""
                SELECT *
                FROM captures
                WHERE ip_dst IN ('{in_dst}','{in_src}') AND ip_src IN ('{in_dst}','{in_src}')
                LIMIT 10000;
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
            
def get_new_capture(in_id):
    """Função que busca por capturas de trafego entre dois ips
    
    Args:
        in_id_pcap (string): id do pcap que será buscado
    
    Returns:
        out_dt (datatable): dados de todas as conexões correspondentes neste fluxo
    
    """
    conn = conn_db()
    if conn:
        try:
            str_query = f"""
                            SELECT *
                            FROM captures
                            WHERE id_pcap = {in_id}
                            ORDER BY id_pcap ASC
                            LIMIT 1
                        """
            cursor = conn.cursor()
            cursor.execute(str_query)
            tpl_data = cursor.fetchall()
            cursor.close()
            conn.commit()
            conn_db(conn)
                        
            out_dict = convert_tuple_to_dict(tpl_data)
            return out_dict
            
        except Exception as e:
            print("Erro ao extrair dados com lista de atributos:",str(e))
            conn_db(conn)
            
def insert_error(in_process, in_description):
    """Função que insere dados de erros no banco
    
    Args:
        in_process (string): nome do processo que está sendo executado
        in_description (string): descrição reduzida do erro
        
    Returns:
        id_error (int): id do erro criado
    """
    
    description = in_description.replace("'","")
    
    insert_query = f"""
                INSERT INTO errors (process_name, description)
                VALUES ('{in_process}', '{description}')
                RETURNING id_error;
                """
    conn = conn_db()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(insert_query)
            id_error = cursor.fetchall()[0][0]
            conn.commit()
            cursor.close()
            conn_db(conn)
            print("Inserção do ERRO", id_error,"realizada com sucesso!")
            return id_error
        
        except Exception as e:
            conn_db(conn)
            print("Erro ao inserir ERRO:", str(e))