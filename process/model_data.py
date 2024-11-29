import pandas as pd
import numpy as np

def get_mean_win_fwd(in_fwd_pcaps):
        try:
            if len(in_fwd_pcaps)>0:
                out_mean_win_fwd = int(in_fwd_pcaps["TCP Window Size"].mean())
                return out_mean_win_fwd
            return 0
        
        except Exception as e:
            print("Erro ao calcular dados do PCAP:",str(e))
            return None
            
def get_init_win_bwd(in_bwd_pcaps):
    if len(in_bwd_pcaps)>0:
        out_mean_win_bwd = int(in_bwd_pcaps["TCP Window Size"].mean())
        return out_mean_win_bwd
    return 0
    
def get_packets(in_pcaps):
    if len(in_pcaps) > 0:
        min_time_pck = int(in_pcaps["Timestamp"].min())
        max_time_pck = int(in_pcaps["Timestamp"].max())
        count_pck = len(in_pcaps)
        time_diff = max_time_pck - min_time_pck
        if time_diff != 0:
            out_pcks = count_pck/(time_diff)
            return out_pcks
        return count_pck
    return 0

def get_iat(in_data):
        ascending_data = in_data.sort_values(by=["Timestamp"], ascending=True)
        diff_data = ascending_data["Timestamp"].diff()
        out_iat_max = diff_data.max()
        out_iat_min = diff_data.min()
        out_iat_mean = diff_data.mean()
        if np.isnan(out_iat_max):
            out_iat_max, out_iat_min, out_iat_mean = [0, 0, 0]
        return out_iat_max, out_iat_min, out_iat_mean