#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import pandas as pd

from config_ports import d_app_ports

from make_logs import make_log_tcp
from make_logs import make_log_rtp
from make_logs import make_log_udp

from find_server_geolocation import find_server_geolocation

import subprocess
import os
import json
import glob
import sys



def pcapng_to_pcap(in_pcap, out_pcap):


    #Extract TLS
    command = ["tshark", "-F", "pcap", "-r", in_pcap, "-w", out_pcap]
    p1 = subprocess.Popen(command, stdout = subprocess.PIPE, stderr = None, encoding='utf-8')
    try:
        output_tls, erroor = p1.communicate()
    except Exception as e:
        print ("Error in converting pcapng to pcap: " + str(e))
        p1.kill()



def run_tstat(pcap):

    #Extract TLS
    command = ["tstat", pcap]
    p1 = subprocess.Popen(command, stdout = subprocess.PIPE, stderr = None, encoding='utf-8')
    try:
        output_tls, erroor = p1.communicate()
    except Exception as e:
        print ("Error in converting pcapng to pcap: " + str(e))
        p1.kill()






#%%

if __name__ == "__main__":


    big_folder = sys.argv[1]
    num_app = int(sys.argv[2])
    tstat_done = int(sys.argv[3])
    #big_folder = "/home/dena/Pcaps/Pcaps_from_Windows"
    pcaps_readable = True
    #tstat_done = 1
    seconds_before = 10


    list_big_folder = big_folder.split("/")
    list_big_folder = [i for i in list_big_folder if i != ""]
    len_big_folder = len(list_big_folder)

    i=0
    d_app_pcaps = {}

    #Find pcaps to elaborate in put them in d_app_pcaps
    for (root,dirs,files) in os.walk(big_folder, topdown=True):

        if len(files):

            pcaps_to_elaborate = [os.path.join(root, name) for name in files \
                                  if (name.endswith("pcapng") | name.endswith("pcap"))]

            if pcaps_to_elaborate:
                #for Dena 1, for Antonio put 2
                app_name = os.path.dirname(os.path.join(root,files[0])).split("/")[len_big_folder+int(num_app)]
                print("App_name = ", app_name)

                if app_name not in d_app_pcaps.keys():
                    d_app_pcaps[app_name] = []

                for pcap in pcaps_to_elaborate:
                    d_app_pcaps[app_name].append(pcap)

        i+=1


    #print(d_app_pcaps)

    d_app_pcaps_updated = {}


    #Loop to make them pcap if needed & run tstat
    for key, pcap_list in d_app_pcaps.items():
        if pcap_list:
            print("\nElaborating pcaps of ", key)
            if key not in d_app_pcaps_updated.keys():
                d_app_pcaps_updated[key] = []
            for value in pcap_list:
                print("Working on: ", value)
                pcap_name = os.path.basename(value)
                if (pcap_name.startswith("Michela") | \
                    pcap_name.startswith("Ico") |\
                    pcap_name.startswith("Rosa") |\
                    pcap_name.startswith("Alessandro_De") |\
                    (pcap_name.startswith("Maurizio") & pcap_name.endswith("pcapng")) |
                    (pcap_name.startswith("Martino") & pcap_name.endswith("pcapng"))
                    ):
                    in_pcap = value
                    app = key
                    out_pcap = os.path.join(os.path.dirname(value),
                                            os.path.basename(value).split(".")[0]+".pcap"
                                            )
                    if not pcaps_readable:
                        pcapng_to_pcap(in_pcap, out_pcap)
                    value = out_pcap
                    print("New pcap name: ", value)

                if not tstat_done:
                    run_tstat(value)

                if value not in d_app_pcaps_updated[key]:
                    d_app_pcaps_updated[key].append(value)

#%%

    #Loop to elaborate logs and write output to file

    #Write domains to file
    output_path = big_folder
    output_file = os.path.join(output_path, "rtp_tcp_new.json")
    #print("Output file: ", output_file)

    d = dict.fromkeys(["app", "pcap_name", "tcp_before", "rtp_flows", "tcp_all", "udp_all", "rtp_start", "from_udp"])
    f = open(output_file,"w+")
    counter=0

    for key, pcap_list in d_app_pcaps_updated.items():
        if pcap_list:
            print("\nElaborating logs of ", key)
            for value in pcap_list:
                print("Working on: ", value)
                pcap_name = os.path.basename(value)

                d["app"] = key
                d["pcap_name"] = pcap_name

                try:
                    log_rtp_path = glob.glob(value+".out/*/log_mm_complete")[0]
                    log_udp_path = glob.glob(value+".out/*/log_udp_complete")[0]
                    log_tcp_path = glob.glob(value+".out/*/log_tcp_complete")[0]
                except Exception as e:
                    print("Error in finding path to logs: ", e)

                log_tcp_df = make_log_tcp(log_tcp_path)
                log_rtp_df = make_log_rtp(log_rtp_path)
                log_udp_df = make_log_udp(log_udp_path)


                d["tcp_all"] = log_tcp_df.to_dict(orient="list")
                            #[['s_ip:15', 'c_tls_SNI:116', 'first:29']]\
                d["udp_all"] = log_udp_df.to_dict(orient="list")




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

                    clis = find_server_geolocation(log_udp_df["s_ip:10"].tolist())
                    needed_rtp = needed_rtp.join(clis)

                    d["tcp_before"] = needed_tcp[['s_ip:15', 'c_tls_SNI:116', 'first:29']].to_dict(orient="list")
                    d["rtp_flows"] = needed_rtp.to_dict(orient="list")
                    d["rtp_start"] = rtp_start
                    d["from_udp"] = True
                    #print("Needed TCP has timestamps, domains: \n", pd.to_datetime(needed_tcp["first:29"], unit="ms"), needed_tcp["c_tls_SNI:116"])
                    print("RTP start at: ", pd.to_datetime(rtp_start, unit="s"))

                else:
                    if not log_rtp_df[log_rtp_df["a_proto:1"] == "R"].empty:
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

                        clis = find_server_geolocation(log_rtp_df["s_ip:10"].tolist())
                        needed_rtp = needed_rtp.join(clis)

                        d["tcp_before"] = needed_tcp[['s_ip:15', 'c_tls_SNI:116', 'first:29']].to_dict(orient="list")
                        d["rtp_flows"] = needed_rtp.to_dict(orient="list")
                        d["rtp_start"] = rtp_start
                        d["from_udp"] = False

                        #print("Needed TCP has timestamps, domains: \n", pd.to_datetime(needed_tcp["first:29"], unit="ms"), needed_tcp["c_tls_SNI:116"])
                        print("\nRTP start at: ", pd.to_datetime(rtp_start, unit="s"))
                    else:
                        print("There is a log RTP with only RTCP ", pcap_name)

                json.dump(d, f)
                f.write("\n")
                counter +=1
    f.close()

    print("I have elaborated " + str(counter) + " files.")



#%%














