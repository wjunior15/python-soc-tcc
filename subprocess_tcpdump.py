import subprocess as sub
import csv
import config

def get_pcaps(pcap_file, pcap_count):
    """
    Função que cria o arquivo .pcap com os dados de rede e depois coleta as informações registradas nele pelo tcpdump do linux bash.
    
    Args:
        pcap_file (string): Caminho do arquivo .pcap onde os dados do tcpdump serão registrados
        pcap_count (int): Quantidade de conexões que devem ser registradas
        
    Returns:
        output_content (list): Lista de dados processados pelo tshark com informações dos registros
    """
    tcpdump_script = f"sudo tcpdump -i eth0 -w {pcap_file} -c {pcap_count}"
    sub.run(tcpdump_script, shell = True)

    tshark_script = (
        f"tshark -r {pcap_file} -T fields -e ip.src -e ip.dst "
        f"-e tcp.srcport -e tcp.dstport -e frame.time_relative "
        f"-e tcp.flags -e tcp.window_size -E header=y -E separator=,"
    )

    output_content = sub.check_output(tshark_script, shell=True).decode().splitlines()
    return output_content


def write_csv(csv_file, pcap_content):
    """
    Função que cria o arquivo .csv com os dados que serão processados para o modelo (IP, Ports, Timestamp, Flags, Win_Size)
    
    Args:
        csv_file (string): Caminho do arquivo .csv onde os dados serão registrados
        pcap_content (list): Lista de dados processados pelo tshark com informações dos registros
    """
    
    with open(csv_file, 'w', newline='') as csvFile:
        csv_writer = csv.writer(csvFile)
        csv_writer.writerow(["IP Source", "IP Destination", "Source Port", "Destination Port", "Timestamp", "SYN Flag", "ACK Flag", "TCP Window Size"])
        
        for line in pcap_content[1:]:
            fields = line.split(',')
            
            if len(fields) < 7:
                continue
            
            sync_flag = 0
            ack_flag = 0
            if str(fields[5]) != '':
                tcp_flags = int(fields[5], 16)
                sync_flag = 1 if tcp_flags & 0b000010 else 0
                ack_flag = 1 if tcp_flags & 0b10000 else 0
            
            csv_writer.writerow([fields[0], fields[1], fields[2], fields[3], fields[4], sync_flag, ack_flag, fields[6]])
            
    print(f"Dados salvos com sucesso no arquivo {csv_file}")
    
def main():
    pcap_file = config.PATH_CAPTURE_PCAP
    csv_file = config.PATH_CSV_PCAP

    pcap_content = get_pcaps(pcap_file, 50)
    write_csv(csv_file, pcap_content)
    
if __name__ == '__main__':
    main()