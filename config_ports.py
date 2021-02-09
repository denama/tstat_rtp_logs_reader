#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import numpy as np

d_app_ports = {

        "facetime": np.arange(3478, 3498, 1).tolist() + np.arange(16384, 16388, 1).tolist() + np.arange(16393, 16403, 1).tolist(),
        "whatsapp": [3478, 45395, 50318, 59234],
        "zoom": [3478, 3479, 5090, 8801, 8802, 8803, 8804, 8805, 8806, 8807, 8808, 8809, 8810],
        "skype": [3478, 3480],
        "msteams": [3478, 3479, 3480, 3481],
        "webex_teams": [5004],
        "webex_meetings": [],
        "google_meet": np.arange(19302, 19310, 1).tolist(),
        "bbb": [29106, 29839, 31225],
        "instagram": [],
        "facebook": [40002, 60323, 61230],
        "goto_meeting": [1853, 8200] + np.arange(3000, 4001, 1).tolist(),
        "telegram": [],
        "house_party": [],

        }