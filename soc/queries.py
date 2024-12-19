import config
import psycopg2 as psy
import numpy as np
import time

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
                DROP TABLE IF EXISTS alerts, captures, errors;

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
                    label varchar(50),
                    cap_status varchar(50),
                    CONSTRAINT PK_pcap PRIMARY KEY (id_pcap)
                );

                CREATE TABLE alerts(
                    id_alert SERIAL,
                    id_pcap integer,
                    label varchar(50) NOT NULL,
                    mean_win_fwd integer,
                    mean_win_bwd integer,
                    ack_count integer,
                    syn_count integer,
                    fwd_pck decimal(8,2),
                    bwd_pck decimal(8,2),
                    iat_max decimal(8,2),
                    iat_min decimal(8,2),
                    iat_mean decimal(8,2),
                    ports_number integer,
                    status varchar(50),
                    CONSTRAINT PK_alert PRIMARY KEY (id_alert, id_pcap),
                    CONSTRAINT FK_alert_pcap FOREIGN KEY (id_pcap) REFERENCES captures(id_pcap)
                );
                
                CREATE TABLE errors(
                    id_error SERIAL,
                    process_name VARCHAR(50) NOT NULL,
                    description VARCHAR (255) NOT NULL,
                    CONSTRAINT PK_error PRIMARY KEY (id_error)
                );
                
            """)
            conn.commit()
            cursor.close()
            conn_db(conn)
            print(f"Criação do banco executada com sucesso!")
        except Exception as e:
            print(f"Erro ao criar banco:",str(e))
            conn_db(conn)

def insert_pcap_data(in_pcap, in_label):
    """Função realiza inserção de pcaps na tabela de captures e retorna o id do item criado.
    
    Args:
        in_pcap (list): lista com valores do trafego de rede
        
    Returns:
        id_pcap (int): id da linha inserida no banco de dados
    """
    conn = conn_db()
    if conn:
        try:
            str_insert = f"""INSERT INTO captures (ip_src, ip_dst, src_port, dst_port, timestamp_conn, syn_flag, ack_flag, win_size, label, cap_status) VALUES ('{in_pcap[0]}', '{in_pcap[1]}', '{in_pcap[2]}', '{in_pcap[3]}', {np.round(float(in_pcap[4]),8)}, {in_pcap[5]}, {in_pcap[6]}, {np.round(float(in_pcap[7]),8)}, '{in_label}', 'NEW') RETURNING id_pcap;"""
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
            
def insert_error(in_process, in_description):
    """Função que insere dados de erros no banco
    
    Args:
        in_process (string): nome do processo que está sendo executado
        in_description (string): descrição reduzida do erro
        
    Returns:
        id_error (int): id do erro criado
    """
    insert_query = f"""
                INSERT INTO alerts (process_name, description)
                VALUES ('{in_process}', '{in_description}')
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