import config
import queries
import traceback
import os
import model_data as md

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
    
    #Init Win Bytes Fwd - Apenas Flag SYN
    init_win_fwd = md.get_init_win_fwd(raw_data, ip_src, ip_dst)
    print("Init Win Fwd",init_win_fwd)
    
    #Success in Get Init Window Bytes Fwd
    if init_win_fwd:
        print("Win Size", win_size)
        
        #Init Win Bytes Bwd - Flag SYN e ACK
        init_win_bwd = md.get_init_win_bwd(raw_data, ip_src, ip_dst)
        print("Init Win Bwd", init_win_bwd)
        
        #Fwd Packets/s
        fwd_pkg_s = md.get_fwd_packets(raw_data, ip_src, ip_dst, timestamp)
        print("Fwd Packets/s",fwd_pkg_s)
        
        #Bwd Packets/s
        bwd_pkg_s = md.get_bwd_packets(raw_data, ip_src, ip_dst, timestamp)
        print("Bwd Packets/s",bwd_pkg_s)
        
        #IAT
        iat_max, iat_min, iat_mean = md.get_iat(raw_data, arr_ips, timestamp)
        print("IAT Max",iat_max,"| IAT Médio", iat_mean,"| IAT Minímo", iat_min)
        
        #Flow Duration
        flow_duration = md.get_flow_duration(raw_data, arr_ips, timestamp)
        print("Flow Duration",flow_duration)
            
        #Subflow Backward Bytes
        subflow_bwd = md.get_subflow_bwd(raw_data, ip_src, ip_dst, timestamp)
        print("Subflow Bwd", subflow_bwd)
        print("Timestamp",pcap[4])
        
        data_rna = {"Init_Win_bytes_forward":init_win_fwd,
                             "ACK Flag Count":ack_flag,
                             "Fwd Packets/s":fwd_pkg_s,
                             "Flow Packets/s":bwd_pkg_s,
                             "Flow IAT Max":iat_max,
                             "Flow IAT Min":iat_min,
                             "Flow Duration":flow_duration,
                             "Init_Win_bytes_backward":init_win_bwd,
                             "Subflow Bwd Bytes":subflow_bwd,
                             "Flow IAT Mean":iat_mean,
                             "Label":None,
                             "Source":ip_src,
                             "Destiny":ip_dst,
                             "Timestamp":pcap[4]}
        
        return data_rna
    return None

def main():
    try:        
        print("---- INICIA PROCESS on",config.SYSTEM_NAME,"version",config.CODE_VERSION, "----")
        
        INDEX = 0
        INIT_TIME = 0
        while 1:
            try:
                dict_pcap = queries.get_new_capture()
                if not dict_pcap:
                    continue
                
                id_pcap = dict_pcap["ID"]
                queries.update_status_captures(id_pcap, "RUNNING")
                
                ip_src = dict_pcap["IP Source"]
                ip_dst = dict_pcap["IP Destination"]
                port_src = dict_pcap["Source Port"]
                port_dst = dict_pcap["Destination Port"]
                timestamp = dict_pcap["Timestamp"]
                syn_flag = dict_pcap["SYN Flag"]
                ack_flag = dict_pcap["ACK Flag"]
                win_size = dict_pcap["TCP Window Size"]
                label = dict_pcap["Label"]
                list_pcap = [ip_src, ip_dst, port_src, port_dst, timestamp, syn_flag, ack_flag, win_size]
                
                if INDEX == 0:
                    INIT_TIME = timestamp
                
                #No analyse if this is unique pcap in this flow - Infinity error in pck/s
                all_flow_data = queries.get_captures_by_ips(ip_dst, ip_src)
                if len(all_flow_data) == 1:
                    queries.update_status_captures(id_pcap, "PROCESS")
                    continue
                
                data_rna = get_model_attributes_by_pcap_data(list_pcap, all_flow_data, INIT_TIME)
                
                #Invalid data return in list
                if not data_rna:
                    queries.update_status_captures(id_pcap, "PROCESS")
                    continue

                id_alert = queries.insert_alert(id_pcap, data_rna, label)
                queries.update_status_captures(id_pcap, "PROCESS")
                
                INDEX += 1
            except Exception as e:
                error_description = str(e)[0:254]
                print("Error Capture", id_pcap,":",str(e))
                id_error = queries.insert_error("PROCESS", error_description)
                
        
    except Exception as e:
        print("Erro na captura:", str(e))
        print("     ------- Traceback Completo do ERRO -------")
        traceback.print_exc()
    
    except KeyboardInterrupt:
        print(" --- EXECUÇÃO INTERROMPIDA PELO USUÁRIO ---")

if __name__ == '__main__':
    main()
    