import config
import psycopg2 as psy
import numpy as np
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


def get_new_alert():
    """Função que busca por alerts pendentes de processamento
    
    Args:
    
    Returns:
        out_dt (datatable): dados de todas as conexões correspondentes neste fluxo
    
    """
    conn = conn_db()
    if conn:
        try:
            str_query = f"""
                            SELECT *
                            FROM alerts
                            WHERE status = 'NEW'
                            ORDER BY id_alert ASC
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

def update_alert_status(in_id, in_status):
    """Função que atualiza o status de um item no banco de acordo com seu id
    
    Args:
        in_id (int): id do item que será atualizado
        in_new_status (string): novo status que será atribuído    
    """
    conn =   conn_db()
    
    if conn:
        try:
            str_update = f"""
                UPDATE alerts
                SET status = '{in_status}'
                WHERE id_alert = {in_id};
                """
            cursor = conn.cursor()
            cursor.execute(str_update)
            conn.commit()
            cursor.close()
            
            #Encerra conexão criada
            conn_db(conn)
            
            print("Atualização do item",in_id,"realizada com sucesso! Novo Status:", in_status)
            
        except Exception as e:
            conn_db(conn)
            print("Erro ao atualizar status do item",in_id,":",str(e))

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
                        "ID PCAP":item[1],
                        "Label":item[2],
                        "Mean Win Fwd":item[3],
                        "Mean Win Bwd":item[4],
                        "ACK Count":item[5],
                        "SYN Count":item[6],
                        "Fwd Packets":np.round(float(item[7]),2),
                        "Bwd Packets":np.round(float(item[8]),2),
                        "IAT Max":np.round(float(item[9]),2),
                        "IAT Min":np.round(float(item[10]),2),
                        "IAT Mean":np.round(float(item[11]),2),
                        "Ports Number":int(item[12]),
                        "Status":item[13]
                    }
        
        return dict_data
        
    return out_dict

def insert_error(in_process, in_description):
    """Função que insere dados de erros no banco
    
    Args:
        in_process (string): nome do processo que está sendo executado
        in_description (string): descrição reduzida do erro
        
    Returns:
        id_error (int): id do erro criado
    """
    
    description = in_description.replace("'","")[0:254]
    
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