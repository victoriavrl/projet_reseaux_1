import pyshark

#capture = pyshark.FileCapture("C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquet test 1mess\envoye_1mess_4G.pcapng")
# print(dir(capture))
def get_DNS_stats(filepath):
    capture = pyshark.FileCapture(filepath)

    capture.load_packets()

    # https://stackoverflow.com/questions/41417235/pyshark-attribute-error-while-printing-dns-info

    requests_ip_src = []
    query_names = []
    respond_ip_src = []
    respond_names = []

    for i in range(len(capture)):
        try:
            # print("t'es ou")
            if capture[i].dns.qry_name:
                #print("DNS Request from ip source : ", capture[i].ip.src)
                #print("DNS query name : ", capture[i].dns.qry_name)
                requests_ip_src.append(capture[i].ip.src)
                query_names.append(capture[i].dns.qry_name)
        except:
            # ignore captures that aren't DNS Request
            continue
        try:
            if capture[i].dns.resp_name:
                #print("DNS Respond from ip source : ", capture[i].ip.src)
                #print("DNS respond name : ", capture[i].dns.resp_name)  # ce qu'il a demander
                respond_ip_src.append(capture[i].ip.src)
                respond_names.append(capture[i].dns.resp_name)
        except:
            continue

        #TODO : chercher domaine name
        
        print("DNS Request from ip source : ", requests_ip_src)
        print("DNS query names : ", query_names)
        print("DNS Respond from ip sources : ", respond_ip_src)
        print("DNS respond names : ", respond_names)


filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquet test 1mess\envoye_1mess_4G.pcapng"
get_DNS_stats(filepath)