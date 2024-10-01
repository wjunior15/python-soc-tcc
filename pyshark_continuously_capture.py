import pandas as pd
import numpy as np
import tensorflow as tf
import keras
import joblib
from sklearn.preprocessing import LabelEncoder
import subprocess as sub
import config
import queries
import time
import pyshark
import traceback

def import_tf_model(in_model_path):
    """
    Função importa modelo tensorflow treinado previamente.
    
    Args:
        in_model_path (string): Caminho do modelo que será importado
    Returns:
        out_tf_model (tf.model): Modelo de RNA importado
    """
    return keras.models.load_model(in_model_path)

def get_pcap_data(in_pcap, in_time_zero):
    """
    Função extraí os dados necessários dos pcaps.
    
    Args:
        in_pcap (object): Pcap analisado
        in_time_zero (float): Timestamp do item zero coletado
    Returns:
        out_list_pcap (list): Dados extraídos do pcap
    """
    if 'IP' in in_pcap and 'TCP' in in_pcap:
        # Extrai dados
        source_ip = in_pcap.ip.src
        destination_ip = in_pcap.ip.dst
        source_port = in_pcap.tcp.srcport
        destination_port = in_pcap.tcp.dstport
        tcp_flags = in_pcap.tcp.flags
        window_size = in_pcap.tcp.window_size
        timestamp = int(float(in_pcap.sniff_timestamp)) - in_time_zero
        if config.BOOL_USE_DB:
            timestamp = int(float(in_pcap.sniff_timestamp))
        
        sync_flag = 0
        ack_flag = 0
        if str(tcp_flags) != '':
                tcp_flags = int(tcp_flags, 16)
                sync_flag = 1 if tcp_flags & 0b000010 else 0
                ack_flag = 1 if tcp_flags & 0b10000 else 0
                
        out_list_pcap = [source_ip, destination_ip, source_port, destination_port, timestamp, sync_flag, ack_flag, window_size]
        return out_list_pcap

def import_encoder(in_encoder_path):
    """
    Função que faz a importação do modelo pré-treinado de LabelEncoder
    
    Args:
        in_encoder_path (string): Caminho do modelo
    Returns:
        le (LabelEncoder): Modelo pré-treinado de LabelEncoder
    """
    return joblib.load(in_encoder_path)

def print_end_time(in_init_time):
    """
    Função que faz a impressão do tempo total de execução do processo.
    
    Args:
        in_encoder_path (int): Timestamp do tempo de inicio de execução do processo
    """
    print("Tempo total de execução da captura:",str(int(time.time())-in_init_time),"segundos")

def define_list_to_query_by_att(in_ip_src, in_ip_dst):
    out_list_names = ['ip_src', 'ip_dst']
    out_list_values = [f"('{in_ip_src}', '{in_ip_dst}')", f"('{in_ip_src}', '{in_ip_dst}')"]
    out_list_conditions = ['IN', 'IN']
    out_and_or = "AND"
    return out_list_names, out_list_values, out_list_conditions, out_and_or

def get_model_attributes_by_pcap_data(pcap, raw_data, timestamp_zero):
    """
    Função que extrai os dados que serão utilizados no modelo RNA
    
    Args:
        pcap (dataframe_row): Linha de dados que representa uma conexão TCP
        raw_data (dataframe): Dataframe contendo todos os dados de PCAPs
    Returns:
        out_list_rna (list): Lista contendo o dicionário com os dados para o modelo extraídos do PCAP
    """
    #Define valores do item analisado
    ip_src = pcap[0]
    ip_dst = pcap[1]
    timestamp = pcap[4] - timestamp_zero
    syn_flag = pcap[5]
    ack_flag = pcap[6]
    win_size = pcap[7]
    
    #Inicializa valores do fluxo analisado
    arr_ips = [ip_src, ip_dst]
    real_ip_src = None
    real_ip_dst = None
    init_win_fwd = None
    init_win_bwd = None
    fwd_pkg_s = 1
    bwd_pkg_s = 1
    
    #Init Win Bytes Fwd - Apenas Flag SYN
    fwd_pcaps = raw_data.query('`SYN Flag` == 1 & `ACK Flag` == 0 & `IP Source` in @arr_ips & `IP Destination` in @arr_ips')
    if len(fwd_pcaps)>0:
        init_win_fwd = int(fwd_pcaps.iloc[0,-1])
        real_ip_src = fwd_pcaps.iloc[0,0]
        real_ip_dst = fwd_pcaps.iloc[0,1]
    
    #Init Win Bytes Bwd - Flag SYN e ACK
    bwd_pcaps = raw_data.query('`SYN Flag` == 1 & `ACK Flag` == 1 & `IP Source` in @arr_ips & `IP Destination` in @arr_ips')
    if len(bwd_pcaps)>0:
        init_win_bwd = int(bwd_pcaps.iloc[0,-1])
    
    if real_ip_dst and real_ip_dst:
        #Fwd Packets/s
        fwd_pck = raw_data.query('`IP Source` == @real_ip_src & `IP Destination` == @real_ip_dst')
        min_time_pck = fwd_pck["Timestamp"].min()
        count_pck = len(fwd_pck)
        time_diff = timestamp - min_time_pck
        if time_diff != 0:
            fwd_pkg_s = count_pck/(time_diff)
        
        #Bwd Packets/s
        bwd_pck = raw_data.query('`IP Source` == @real_ip_dst & `IP Destination` == @real_ip_src')
        min_time_pck = bwd_pck["Timestamp"].min()
        count_pck = len(bwd_pck)
        time_diff = timestamp - min_time_pck
        if time_diff != 0:
            bwd_pkg_s = count_pck/time_diff
        
        #IAT
        data_diff_IAT = raw_data.query('`IP Source` in @arr_ips & `IP Destination` in @arr_ips & `Timestamp` <= @timestamp').sort_values(by=["Timestamp"])["Timestamp"].diff()
        iat_max = data_diff_IAT.max()
        iat_min = data_diff_IAT.min()
        iat_mean = data_diff_IAT.mean()
        if np.isnan(iat_max):
            iat_max, iat_min, iat_mean = [0, 0, 0]
        
        #Flow Duration
        data_flow_duration = raw_data.query('`IP Source` in @arr_ips & `IP Destination` in @arr_ips & `Timestamp` <= @timestamp')["Timestamp"]
        flow_duration = data_flow_duration.max() - data_flow_duration.min()
        if np.isnan(flow_duration):
            flow_duration = 0
            
        #Subflow Backward Bytes
        data_subflow = raw_data.query('`IP Source` == @real_ip_dst & `IP Destination` == @real_ip_src & `Timestamp` <= @timestamp')
        sum_bytes = data_subflow["Timestamp"].sum()
        
        data_rna = {"Init_Win_bytes_forward":init_win_fwd,
                             "ACK Flag Count":ack_flag,
                             "Fwd Packets/s":fwd_pkg_s,
                             "Flow Packets/s":bwd_pkg_s,
                             "Flow IAT Max":iat_max,
                             "Flow IAT Min":iat_min,
                             "Flow Duration":flow_duration,
                             "Init_Win_bytes_backward":init_win_bwd,
                             "Subflow Bwd Bytes":sum_bytes,
                             "Flow IAT Mean":iat_mean,
                             "Label":None,
                             "Source":ip_src,
                             "Destiny":ip_dst,
                             "Timestamp":pcap[4]}
        
        out_list_rna = [data_rna]
        return out_list_rna

def decoder_data(in_le, in_predictions):
    """
    Realiza a decodificação dos dados retornados pelo modelo.
    
    Args:
        in_le (LabelEncoder): Modelo de Encoder pré-treinado e importado para uso.
        in_predictions (np.array): Array de dados retornados pelo modelo tf.
    Returns:
        out_arr_decoded_labels (np.array): Array de dados decodificados pelo LabelEncoder.
    """
    list_argmax = []
    for item in in_predictions:
        list_argmax.append(np.argmax(item))
        
    arr_encoded_labels = np.array(list_argmax)
    out_arr_decoded_labels = in_le.inverse_transform(arr_encoded_labels)
    return out_arr_decoded_labels

def normalize_data_column(in_column, in_maxValue):
    """
    Função que normaliza todos os dados de uma coluna
    
    Args:
        in_column (dataframe_column): Coluna que será normalizada
        in_maxValue (int): Valor máximo da coluna utilizado para normalização
    Returns:
        out_column_normalized (dataframe_column): Coluna normalizada
    """
    return in_column/in_maxValue

def build_data_to_model_format(in_arr_data, in_dict_maxValues):
    """
    Função que extrai os dados que serão utilizados no modelo RNA
    
    Args:
        in_arr_data (list): Lista de dados a serem utilizados no modelo
        in_dict_maxValues (dict): Dict de valores máximos para serem utilizados para normalização dos dados
    Returns:
        out_dt_data (np.array): Array de dados pronto para uso no modelo tf
    """
    dt_data = pd.DataFrame.from_dict(in_arr_data)
    dt_data.drop(labels=["Label", "Source", "Destiny", "Timestamp"], axis=1, inplace=True)
    
    for c in dt_data.columns:
        dt_data[c] = normalize_data_column(dt_data[c], in_dict_maxValues[c])
    dt_data.fillna(value=0, inplace=True)
    out_dt_data = dt_data.to_numpy()
    return out_dt_data

def predict_with_model(in_list_data_rna, in_model, in_le):
    """
    Função que faz a predição de dados através do modelo importado.
    
    Args:
        arr_data_rna (list): Lista de dados dos pcaps com os atributos utilizados pelo modelo RNA
        model (tf_model): Modelo pré-treinado do tensorflow
        
    Returns:
        out_arr_predict_decode (np.array): List de retorno do modelo já decodificados para análise
    """
    arr_data_to_model = build_data_to_model_format(arr_data=in_list_data_rna, dict_maxValues=config.DICT_MAX_VALUES)
    arr_predict = in_model.predict(arr_data_to_model)
    out_arr_predict_decode = decoder_data(le=in_le, predictions=arr_predict)
    return out_arr_predict_decode

def get_malign_pcaps(in_item_predict_decode, in_arr_data_rna):
    """
    Função que trata pcaps considerados ALERTAS pelo modelo de RNA
    
    Args:
        in_item_predict_decode (string): Label definido pela RNA
        in_arr_data_rna (list): Lista contendo o dicionário de dados do pcap com os atributos utilizados pelo modelo RNA
    """
    print(in_arr_data_rna[0]['Source']," -> ",in_arr_data_rna[0]["Destiny"]," | Warning: ",in_item_predict_decode, " | Timestamp: ", in_arr_data_rna[0]['Timestamp'])
    queries.update_status_captures(in_arr_data_rna[0]['Source'], in_arr_data_rna[0]['Destiny'], in_arr_data_rna[0]['Timestamp'], "ALERT", None)
    queries.insert_alert(in_arr_data_rna[0], in_item_predict_decode)
    
def get_benign_pcaps(in_arr_data_rna):
    """
    Função que trata pcaps considerados NORMAIS pelo modelo de RNA
    
    Args:
        in_arr_data_rna (list): Lista contendo o dicionário de dados do pcap com os atributos utilizados pelo modelo RNA
    """
    print("  --- BENIGN PCAP ---")
    queries.update_status_captures(in_arr_data_rna[0]['Source'], in_arr_data_rna[0]['Destiny'], in_arr_data_rna[0]['Timestamp'], "BENIGN", None)

def get_model_number():
    """
    Função que faz a validação da entrada de dados do usuário para seleção do tipo de modelo a ser carregado.
        
    Returns:
        int_number (int): Número do modelo que será carregado
    """
    range_modelos = range(1,5)
    int_number = int(input("Type model and encoder number [1-4]: "))
    if int_number in range_modelos:
        return int_number
    print("Número de modelo indisponível - Insira um número dentro do range: ",range_modelos)
    get_model_number()

def get_model_and_encoder():
    """
    Função que faz a importação dos modelos de RNA e encoder de dados.
        
    Returns:
        out_le (encoder): Modelo de encoder de dados pré-treinado.
        out_model (tf_model): Modelo pré-treinado do tensorflow.
    """
    
    int_number = get_model_number()
    print(" --- Número selecionado:",int_number)
    le_path = config.DICT_ACTIVE_MODEL_AND_ENCODER[int_number]["encoder"]
    model_path = config.DICT_ACTIVE_MODEL_AND_ENCODER[int_number]["model"]
    
    out_le = import_encoder(le_path)
    print(" --- Encoder de dados importado com sucesso!")
    out_model = import_tf_model(model_path)
    print(" --- Modelo TF importado com sucesso!")
    
    return out_le, out_model

def main():
    try:
        init_exec_time = int(time.time())
        print("     ---- INICIA PYTHON SOC ----")
        le, model = get_model_and_encoder()
        print(" --- Inicia Coleta de PCAPs")
        capture = pyshark.LiveCapture(interface=config.PYSHARK_CAPTURE_INTERFACE)
        for pcap in capture.sniff_continuously():
            if 'IP' in pcap and 'TCP' in pcap:
                list_pcap = get_pcap_data(pcap, int(init_exec_time))
                
                if list_pcap:
                    queries.insert_pcap_data(list_pcap)
                    #No analyse if this is sync pcap - Infinity error in pck/s 
                    if list_pcap[5] == 1:
                        continue
                    
                    name_list, value_list, condition_list, and_or = define_list_to_query_by_att(list_pcap[0], list_pcap[1])
                    raw_data = queries.get_captures_by_attribute_list(name_list, value_list, condition_list, and_or)
                    list_data_rna = get_model_attributes_by_pcap_data(list_pcap, raw_data, init_exec_time)
                    
                    if list_data_rna:
                        queries.update_status_captures(list_data_rna[0]['Source'], list_data_rna[0]['Destiny'], list_data_rna[0]['Timestamp'], "RUNNING", None)
                        item_predicted_decode = predict_with_model(list_data_rna, model, le)[0]
                        
                        if not item_predicted_decode == "BENIGN":
                            get_malign_pcaps(item_predicted_decode, list_data_rna)
                            continue
                        
                        get_benign_pcaps(list_data_rna)
                        
        print_end_time(init_exec_time)
        
    except Exception as e:
        print_end_time(init_exec_time)
        print("Erro na captura:", str(e))
        print("     ------- Traceback Completo do ERRO:")
        traceback.print_exc()
    
    except KeyboardInterrupt:
        print_end_time(init_exec_time)
        print(" --- EXECUÇÃO INTERROMPIDA PELO USUÁRIO")


if __name__ == '__main__':
    main()