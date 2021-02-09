#Code to map IP adresses to ASNs and geolocations (organization, country, city) For now, writes everything in a csv. Make it update a csv (like Fra)

import geoip2.database
import pandas as pd
import pyasn
import os


def find_server_geolocation(list_servers):

    def asnOrg(x):
        try:
            response = geoAsndb.asn(x)
            return response.autonomous_system_organization
        except:
            return float('nan')

    def asnGeoloc(x):
        try:
            response = geoCitydb.city(x)
            return [response.country.iso_code,response.city.name,response.location.latitude,response.location.longitude]
        except:
            return float('nan'), float('nan'), float('nan'), float('nan')

    #Load the geoip databases
    geoAsndb = geoip2.database.Reader(os.path.join('GeoIP', 'GeoLite2-ASN.mmdb'))
    geoCitydb = geoip2.database.Reader(os.path.join('GeoIP', 'GeoLite2-City.mmdb'))
    geoCountrydb = geoip2.database.Reader(os.path.join('GeoIP', 'GeoLite2-Country.mmdb'))

    #Load the pyasn database table for ASN
    asndb  = pyasn.pyasn(os.path.join('Pyasn', 'ipasn_20200121.dat'))

    clis = pd.DataFrame(list_servers, columns=["Server_IP"])
    clis["asn_lookup"] = clis['Server_IP'].apply(asndb.lookup)
    clis["ASN"]= clis["asn_lookup"].apply(lambda x: str(x[0]))
    clis["prefix"] = clis["asn_lookup"].apply(lambda x: str(x[1]))
    clis = clis.drop("asn_lookup", axis=1)

    clis['Organization'] = clis["Server_IP"].apply(asnOrg)

    clis['Country_boh'] =  clis['Server_IP'].apply(asnGeoloc)
    clis['Country_ISO'] =  clis['Country_boh'].apply(lambda x: x[0])
    clis['City'] =  clis['Country_boh'].apply(lambda x: x[1])
    clis['LAT'] =  clis['Country_boh'].apply(lambda x: x[2])
    clis['LONG'] =  clis['Country_boh'].apply(lambda x: x[3])
    clis = clis.drop("Country_boh", axis=1)

    #clis.to_csv('./servers_asn_name_tcp1.csv')
    return clis







