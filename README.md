## About

This is a tool to prepare data for RTC_apps_classifier.
It reads a specific folder structure of pcaps, elaborates them with tstat, then using the RTP and TCP logs takes out information from the TCP log about what happened before the RTP communication started and puts them in a *rtp_tcp.json* file.

## Requirements
Needs tstat

## How to organize pcap folder

```
Big_folder
*|
*|__ msteams
*|   |__ pcap1.pcap
*|   |__ pcap2.pcapng
*|
*|
*|__ webex_teams
*|   |__ pcap1.pcap
*|   |__ pcap2.pcapng
*|
*|
*|__ skype
*|   |__ pcap1.pcap
*|   |__ pcap2.pcapng
```
 

## Usage
Run main_window_domains, it takes 3 arguments:
* big_folder --> the folder with all pcaps
* num_app --> which level below the big folder are the folders with app names (if structure as above, 1)
* tstat_done --> have you already run tstat on the pcaps or not

The output is a rtp_tcp.json file with all the info, in *big_folder/*
