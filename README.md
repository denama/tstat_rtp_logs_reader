This is a tool to prepare data for RTC_apps_classifier.
It reads a specific folder structure of pcaps, elaborates them with tstat, then using the RTP and TCP logs takes out information from the TCP log about what happened before the RTP communication started and puts them in a *rtp_tcp.json* file.
