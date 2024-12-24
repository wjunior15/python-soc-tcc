import config
import queries
import traceback
import model_data as md
import socket
import rd_queue

def get_ip_using_socket(hostname):
    try:
        return str(socket.gethostbyname(hostname))
    except socket.error as e:
        print(f"Error: {e}")
        return None

def get_model_attributes_by_pcap_data(pcap, raw_data, ip_soc):
    """
    Função que extrai os dados que serão utilizados no modelo RNA
    
    Args:
        pcap (dataframe_row): Linha de dados que representa uma conexão TCP
        raw_data (dataframe): Dataframe contendo todos os dados de PCAPs
        ip_soc (string): IP do host do soc
    Returns:
        out_list_rna (list): Lista contendo o dicionário com os dados para o modelo extraídos do PCAP
    """
    #Define valores do item analisado
    ip_src = pcap[0]
    ip_dst = pcap[1]
    
    if ip_src == ip_soc:
        ip_src = ip_dst
        ip_dst = ip_soc
    
    if ip_dst == ip_soc:
        ip_dst = ip_soc
    
    syn_flag = pcap[5]
    ack_flag = pcap[6]
    
    print("IP Source", ip_src)
    print("IP Destination", ip_dst)
    #Dados de Fwd e Bwd utilizados na obtenção da variáveis do modelo
    fwd_pck = raw_data.query('`IP Source` == @ip_src & `IP Destination` == @ip_dst')
    bwd_pck = raw_data.query('`IP Source` == @ip_dst & `IP Destination` == @ip_src')
    
    #Mean Win Bytes Fwd - Apenas Flag SYN
    init_win_fwd = md.get_mean_win_size(fwd_pck)
    print("Mean Win Fwd",init_win_fwd)
          
    #Mean Win Bytes Bwd - Flag SYN e ACK
    init_win_bwd = md.get_mean_win_size(bwd_pck)
    print("Mean Win Bwd", init_win_bwd)
    
    #Fwd Packets/s
    fwd_pkg_s = md.get_packets(fwd_pck)
    print("Fwd Packets/s",fwd_pkg_s)
    
    #Bwd Packets/s
    bwd_pkg_s = md.get_packets(bwd_pck)
    print("Bwd Packets/s",bwd_pkg_s)
    
    #IAT
    iat_max, iat_min, iat_mean = md.get_iat(raw_data)
    print("IAT Max",iat_max,"| IAT Médio", iat_mean,"| IAT Minímo", iat_min)
    
    #Ports Number Fwd
    ports_number_fwd = md.get_ports_number(fwd_pck)
    print("Ports Number",ports_number_fwd)
    
    data_rna = {"Mean Win Fwd":init_win_fwd,
                "ACK Flag Count":ack_flag,
                "SYN Flag Count":syn_flag,
                "Fwd Packets/s":fwd_pkg_s,
                "Bwd Packets/s":bwd_pkg_s,
                "Flow IAT Max":iat_max,
                "Flow IAT Min":iat_min,
                "Mean Win Bwd":init_win_bwd,
                "Flow IAT Mean":iat_mean,
                "Ports Number":ports_number_fwd,
                "Label":None,
                "Source":ip_src,
                "Destiny":ip_dst,
                "Timestamp":pcap[4]}
    
    return data_rna

def main():
    try:        
        print("---- INICIA PROCESS on",config.SYSTEM_NAME,"version",config.CODE_VERSION, "----")

        IP_SOC = get_ip_using_socket("soc")
        
        while 1:
            try:
                id_pcap = rd_queue.get_queue_item("captures")
                if not id_pcap:
                    continue
                
                dict_pcap = queries.get_new_capture(id_pcap)
                if not dict_pcap:
                    continue
                
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
                
                #No analyse if this is unique pcap in this flow - Infinity error in pck/s
                all_flow_data = queries.get_captures_by_ips(ip_dst, ip_src)
                
                data_rna = get_model_attributes_by_pcap_data(list_pcap, all_flow_data, IP_SOC)
                
                #Invalid data return in list
                if not data_rna:
                    queries.update_status_captures(id_pcap, "PROCESS")
                    continue

                id_alert = queries.insert_alert(id_pcap, data_rna, label)
                rd_queue.insert_queue_item("alerts", id_alert)
                queries.update_status_captures(id_pcap, "PROCESS")
                
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
    