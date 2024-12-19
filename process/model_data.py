import pandas as pd
import numpy as np

def get_mean_win_size(in_pcaps):
        try:
            if len(in_pcaps)>0:
                out_mean_win_fwd = int(in_pcaps["TCP Window Size"].mean())
                return out_mean_win_fwd
            return 0
        
        except Exception as e:
            print("Erro ao calcular dados do PCAP:",str(e))
            return None
    
def get_packets(in_pcaps):
    if len(in_pcaps) > 0:
        min_time_pck = int(in_pcaps["Timestamp"].min())
        max_time_pck = int(in_pcaps["Timestamp"].max())
        count_pck = len(in_pcaps)
        time_diff = max_time_pck - min_time_pck
        if time_diff != 0:
            pcks_s = count_pck/time_diff
            out_pcks = np.round(pcks_s,2)
            return out_pcks
        return count_pck
    return 0

def get_iat(in_data):
        ascending_data = in_data.sort_values(by=["Timestamp"], ascending=True)
        diff_data = ascending_data["Timestamp"].diff()
        out_iat_max = np.round(diff_data.max(),2)
        out_iat_min = np.round(diff_data.min(),2)
        out_iat_mean = np.round(diff_data.mean(),2)
        if np.isnan(out_iat_max):
            out_iat_max, out_iat_min, out_iat_mean = [0, 0, 0]
        return out_iat_max, out_iat_min, out_iat_mean
    
def get_ports_number(in_data):
    ports_data = in_data["Destination Port"]
    unique_ports = ports_data.unique()
    out_ports_number = len(unique_ports)
    return out_ports_number