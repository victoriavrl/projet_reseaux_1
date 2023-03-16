import pyshark

capture = pyshark.FileCapture("C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquet test 1mess\envoye_1mess_4G.pcapng")

#print(dir(capture))

capture.load_packets()

#https://stackoverflow.com/questions/41417235/pyshark-attribute-error-while-printing-dns-info
for i in range(len(capture)):
    try :
        #print("t'es ou")
        if capture[i].dns.qry_name :
            print()
            print("DNS Request from ip source : ", capture[i].ip.src)
            print("DNS query name : ", capture[i].dns.qry_name)
    except :
        #ignore captures that aren't DNS Request
        continue
    try:
        print(capture[i].dns.resp_name)
        if capture[i].dns.resp_name:
            print("DNS Respond from ip source : ", capture[i].ip.src)
            print("DNS respond name : ", capture[i].dns.resp_name) #ce qu'il a demander
    except :
        continue
    #TODO : chercher domaine name

