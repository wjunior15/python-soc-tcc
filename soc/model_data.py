import pandas as pd
import numpy as np

def get_init_win_fwd(in_data, in_arr_ips):
        try:
            fwd_pcaps = in_data.query('`SYN Flag` == 1 & `ACK Flag` == 0 & `IP Source` in @in_arr_ips & `IP Destination` in @in_arr_ips')
            if len(fwd_pcaps)>0:
                out_init_win_fwd = int(fwd_pcaps.iloc[0,-1])
                out_ip_src = fwd_pcaps.iloc[0,0]
                out_ip_dst = fwd_pcaps.iloc[0,1]
                return out_init_win_fwd, out_ip_src, out_ip_dst
        except Exception as e:
            print("Erro ao calcular dados do PCAP:",str(e))
            return None, None, None
            
def get_init_win_bwd(in_data, in_arr_ips):
    bwd_pcaps = in_data.query('`SYN Flag` == 1 & `ACK Flag` == 1 & `IP Source` in @in_arr_ips & `IP Destination` in @in_arr_ips')
    if len(bwd_pcaps)>0:
        init_win_bwd = int(bwd_pcaps.iloc[0,-1])
        return init_win_bwd
    
def get_fwd_packets(in_data, in_ip_src, in_ip_dst, in_timestamp):
        out_fwd_pcks = 0
        
        fwd_pck = in_data.query('`IP Source` == @in_ip_src & `IP Destination` == @in_ip_dst')
        min_time_pck = fwd_pck["Timestamp"].min()
        count_pck = len(fwd_pck)
        time_diff = in_timestamp - min_time_pck
        if time_diff != 0:
            out_fwd_pcks = count_pck/(time_diff)
            
        return out_fwd_pcks
    
def get_bwd_packets(in_data, in_ip_src, in_ip_dst, in_timestamp):
    out_bwd_pcks = 0
    
    bwd_pck = in_data.query('`IP Source` == @in_ip_src & `IP Destination` == @in_ip_dst')
    min_time_pck = bwd_pck["Timestamp"].min()
    count_pck = len(bwd_pck)
    time_diff = in_timestamp - min_time_pck
    if time_diff != 0:
        out_bwd_pcks = count_pck/time_diff
    
    return out_bwd_pcks

def get_iat(in_data, in_arr_ips, in_timestamp):
        data_diff_IAT = in_data.query('`IP Source` in @in_arr_ips & `IP Destination` in @in_arr_ips & `Timestamp` <= @in_timestamp').sort_values(by=["Timestamp"])["Timestamp"].diff()
        out_iat_max = data_diff_IAT.max()
        out_iat_min = data_diff_IAT.min()
        out_iat_mean = data_diff_IAT.mean()
        if np.isnan(out_iat_max):
            out_iat_max, out_iat_min, out_iat_mean = [0, 0, 0]
        return out_iat_max, out_iat_min, out_iat_mean

def get_flow_duration(in_data, in_arr_ips, in_timestamp):
    data_flow_duration = in_data.query('`IP Source` in @in_arr_ips & `IP Destination` in @in_arr_ips & `Timestamp` <= @in_timestamp')["Timestamp"]
    out_flow_duration = data_flow_duration.max() - data_flow_duration.min()
    if np.isnan(out_flow_duration):
        out_flow_duration = 0
    return out_flow_duration

def get_subflow_bwd(in_data, in_ip_src, in_ip_dst, in_timestamp):
    subflow_data = in_data.query('`IP Source` == @in_ip_dst & `IP Destination` == @in_ip_src & `Timestamp` <= @in_timestamp')
    out_subflow_bwd = subflow_data["Timestamp"].sum()
    return out_subflow_bwd