#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pandas as pd
import numpy as np

from config_ports import d_app_ports

#Elaborate TCP
def make_log_tcp(log_tcp_path):

    with open(log_tcp_path, "r") as f:
        log_tcp = f.readlines()

    log_tcp_df_big = pd.DataFrame([i.split(" ") for i in log_tcp[1:] ], columns=log_tcp[0].split("#")[-1].split(" "))
    log_tcp_df = log_tcp_df_big.loc[:, ['c_ip:1', 'c_port:2', 'c_tls_SNI:116', 'fqdn:127', 's_tls_SCN:117', 's_ip:15', 's_port:16', 's_pkts_all:17', 's_bytes_all:23', 'first:29', 'last:30']]
    log_tcp_df.loc[:, "first:29"] = pd.to_numeric(log_tcp_df.loc[:, "first:29"])
    #log_tcp_df["first_time"] = pd.to_datetime(log_tcp_df.loc[: , "first:29"], unit="ms")
    #log_tcp_df["last_time"] = pd.to_datetime(log_tcp_df.loc[:, "last:30"], unit="ms")

    return log_tcp_df


#Elaborate RTP
def make_log_rtp(log_rtp_path):

    with open(log_rtp_path, "r") as f:
        log_rtp = f.readlines()

    log_rtp_df = pd.DataFrame([i.split(" ") for i in log_rtp[1:] ], columns=log_rtp[0].split("#")[-1].split(" "))
    #log_rtp_df["start_time"] = pd.to_datetime(log_rtp_df.loc[:, "starttime:23"].copy(), unit="s")
    log_rtp_df.loc[:, ["c_port:5", "s_port:11", "packets:15", "starttime:23"]] = \
        log_rtp_df[["c_port:5", "s_port:11", "packets:15", "starttime:23"]].apply(pd.to_numeric, errors="coerce")

    return log_rtp_df


#Elaborate UDP
def make_log_udp(log_udp_path, port_list=None):
    with open(log_udp_path, "r") as f:
        log_udp = f.readlines()

    #udp time is in miliseconds
    log_udp_df = pd.DataFrame([i.split(" ") for i in log_udp[1:] ], columns=log_udp[0].split("#")[-1].split(" "))
    #log_udp_df["c_first_time"] = pd.to_datetime(log_udp_df.loc[:, "c_first_abs:3"].copy(), unit="ms")
    #log_udp_df["s_first_time"] = pd.to_datetime(log_udp_df.loc[:, "s_first_abs:12"].copy(), unit="ms")
    #log_udp_df.loc[:, "c_pkts_all:6"] = pd.to_numeric(log_udp_df.loc[:, "c_pkts_all:6"])
    log_udp_df.loc[:, ["c_port:2", "c_first_abs:3", "c_pkts_all:6", "s_port:11", "s_first_abs:12", "s_pkts_all:15"]] = \
        log_udp_df[["c_port:2", "c_first_abs:3", "c_pkts_all:6", "s_port:11", "s_first_abs:12", "s_pkts_all:15"]].apply(pd.to_numeric, errors="coerce")
    log_udp_df = log_udp_df[log_udp_df["c_pkts_all:6"] >= 250]

    if port_list:
        log_udp_df_2 = log_udp_df[log_udp_df["s_port:11"].astype("int").isin(port_list)]
        if not log_udp_df_2.empty:
            log_udp_df = log_udp_df_2

    log_udp_df = log_udp_df.reset_index()

    return log_udp_df



if __name__ == "__main__":

    #%%
    #main1


#    log_tcp_path = "/home/dena/Documents/Cisco_start/Classifier_domains/Tstat_domains/skype_fra.pcap.out/2020_04_08_14_33.out/log_tcp_complete"
#    log_rtp_path = "/home/dena/Documents/Cisco_start/Classifier_domains/Tstat_domains/skype_fra.pcap.out/2020_04_08_14_33.out/log_mm_complete"

   #log_tcp_path = "/home/dena/Downloads/Antonio_Facetime_Mobile_iOS_3_Audio_Video_Wifi_2.pcapng.out/2020_05_08_00_52.out/log_tcp_complete"
    #log_udp_path = "/home/dena/Downloads/Antonio_Facetime_Mobile_iOS_3_Audio_Video_Wifi_2.pcapng.out/2020_05_08_00_52.out/log_udp_complete"

    #log_udp_path = "/media/dena/TOSHIBA EXT/Pcaps_from_Dropbox/zoom/Luca_Vassio_-_GMzoom.pcap.out/2020_03_27_17_00.out/log_udp_complete"
    #log_tcp_path = "/media/dena/TOSHIBA EXT/Pcaps_from_Dropbox/zoom/Luca_Vassio_-_GMzoom.pcap.out/2020_03_27_17_00.out/log_tcp_complete"

    #For Facetime, take better care of first RTP stream, uses same UDP ports for STUN

    #log_udp_path = "/media/dena/TOSHIBA EXT/Pcaps_from_Dropbox/zoom/Michela_Meo_-_call_zoom-200326.pcap.out/2020_03_26_10_01.out/log_udp_complete"
    #log_tcp_path = "/media/dena/TOSHIBA EXT/Pcaps_from_Dropbox/zoom/Michela_Meo_-_call_zoom-200326.pcap.out/2020_03_26_10_01.out/log_tcp_complete"

    import os
    import glob


    #value = "/home/dena/Documents/Cisco_start/Classifier_domains/Tstat_domains/skype_fra.pcap"
    #value = "/home/dena/Downloads/Antonio_Facetime_Mobile_iOS_3_Audio_Video_Wifi_2.pcapng"
    value = "/home/dena/Pcaps/errors/zoom_2p_dena_gianluca_av_2.pcapng"

    app = "zoom"
    key = app

    seconds_before = 10
    print("Working on: ", value)
    pcap_name = os.path.basename(value)

    try:
        log_rtp_path = glob.glob(value+".out/*/log_mm_complete")[0]
        log_udp_path = glob.glob(value+".out/*/log_udp_complete")[0]
        log_tcp_path = glob.glob(value+".out/*/log_tcp_complete")[0]
    except Exception as e:
        print("Error in finding path to logs: ", e)

    log_tcp_df = make_log_tcp(log_tcp_path)
    log_rtp_df = make_log_rtp(log_rtp_path)
    log_udp_df = make_log_udp(log_udp_path)



    #Is there anything in log_mm_complete?
    #Yes - use (with caution)
    #No - use UDP logs with ports
    if log_rtp_df.empty:
        print("Working from UDP log!\napp: %s, pcap: %s" % (key, pcap_name))

        if key in d_app_ports.keys():
            port_list = d_app_ports[key]
        else:
            port_list = None
        log_udp_df = make_log_udp(log_udp_path, port_list)

        #For Facetime, take better care of first RTP stream, uses same UDP ports for STUN


        first_c = float(log_udp_df.sort_values(by="s_pkts_all:15", ascending=False).loc[:, "c_first_abs:3"].iloc[0])
        first_s = float(log_udp_df.sort_values(by="s_pkts_all:15", ascending=False).loc[:, "s_first_abs:12"].iloc[0])

        if first_c == 0.0:
            rtp_start = first_s / 1000
        elif first_s == 0.0:
            rtp_start = first_c / 1000
        else:
            rtp_start = min(first_c, first_s) / 1000 #to covert to seconds

        needed_tcp = log_tcp_df[((rtp_start - log_tcp_df.loc[:, "first:29"]/1000) > 0) & \
                                ((rtp_start - log_tcp_df.loc[:, "first:29"]/1000) < seconds_before)
                                ]

        needed_rtp = log_udp_df[[
                "c_ip:1", "c_port:2", "c_first_abs:3", "c_pkts_all:6", "s_ip:10", "s_port:11", "s_first_abs:12", "s_pkts_all:15", "fqdn:19"
                ]]


        #print("Needed TCP has timestamps, domains: \n", needed_tcp[["first_time", "c_tls_SNI:116"]])
        print("RTP start at: ", pd.to_datetime(rtp_start, unit="s"))

    else:
        #rtp_start is in seconds, TCP is in miliseconds, we want in seconds
        rtp_start = float(log_rtp_df[log_rtp_df["a_proto:1"] == "R"].loc[:, "starttime:23"].sort_values().iloc[0])
        needed_tcp = log_tcp_df[ \
                                ((rtp_start - log_tcp_df.loc[:, "first:29"]/1000) > 0) & \
                                ((rtp_start - log_tcp_df.loc[:, "first:29"]/1000) < seconds_before)
                                ]
        needed_rtp = log_rtp_df[log_rtp_df["a_proto:1"] == "R"][[
                                 "c_ip:4", "c_port:5",
                                 "s_ip:10", "s_port:11",
                                 "packets:15",
                                 "starttime:23",
                                 "SSRC:27",
                                 "pt_id:32",
                                 ]]

        #print("Needed TCP has timestamps, domains: \n", needed_tcp[["first_time", "c_tls_SNI:116"]])
        print("\nRTP start at: ", pd.to_datetime(rtp_start, unit="s"))


