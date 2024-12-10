import config
import queries
import time
import pyshark
import traceback
import os
import socket
import rd_queue

def get_ip_using_socket(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.error as e:
        print(f"Error: {e}")
        return None

def get_pcap_data(in_pcap):
    """
    Função extraí os dados necessários dos pcaps.
    
    Args:
        in_pcap (object): Pcap analisado
        in_time_zero (float): Timestamp do item zero coletado
    Returns:
        out_list_pcap (list): Dados extraídos do pcap
    """
    # Extrai dados
    source_ip = in_pcap.ip.src
    destination_ip = in_pcap.ip.dst
    source_port = in_pcap.tcp.srcport
    destination_port = in_pcap.tcp.dstport
    tcp_flags = in_pcap.tcp.flags
    window_size = in_pcap.tcp.window_size
    timestamp = int(time.time())
    
    sync_flag = 0
    ack_flag = 0
    if str(tcp_flags) != '':
            tcp_flags = int(tcp_flags, 16)
            sync_flag = 1 if tcp_flags & 0b000010 else 0
            ack_flag = 1 if tcp_flags & 0b10000 else 0
            
    out_list_pcap = [source_ip, destination_ip, source_port, destination_port, timestamp, sync_flag, ack_flag, window_size]
    return out_list_pcap

def main():
    try:
        init_exec_time = int(time.time())
        
        print("---- INICIA PYTHON SOC on",config.SYSTEM_NAME,"version",config.CODE_VERSION, "----")
        queries.create_db()
        
        ip_db = str(get_ip_using_socket("postgres"))
        ip_redis = str(get_ip_using_socket("redis2"))
        ip_metasploit = str(get_ip_using_socket("metasploit"))
        print(" -- IP Banco de Dados",ip_db)
        
        print(" --- Inicia Coleta de PCAPs")
        capture = pyshark.LiveCapture(interface=config.PYSHARK_CAPTURE_INTERFACE)
        print(" --- Capture configurado")
        for pcap in capture.sniff_continuously():
            if 'IP' in pcap and 'TCP' in pcap:
                list_pcap = get_pcap_data(pcap)
                ip_src = str(list_pcap[0])
                ip_dst = str(list_pcap[1]) 
                
                if list_pcap:
                    #No include in db if this connection is between db and soc
                    if ip_src in [ip_db, ip_redis] or ip_dst in [ip_db, ip_redis]:
                        continue
                    label = "BENIGN"
                    if ip_src == ip_metasploit or ip_dst == ip_metasploit:
                        label = "MALIGN"
                        
                    id_pcap = queries.insert_pcap_data(list_pcap, label)
                    rd_queue.insert_queue_item("captures",id_pcap)

        
    except Exception as e:
        print("Erro na captura:", str(e))
        print("     ------- Traceback Completo do ERRO -------")
        traceback.print_exc()
    
    except KeyboardInterrupt:
        print(" --- EXECUÇÃO INTERROMPIDA PELO USUÁRIO ---")

    print("Tempo total de execução da captura:",str(int(time.time())-init_exec_time),"segundos")

if __name__ == '__main__':
    main()
    