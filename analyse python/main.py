import pyshark

capture = pyshark.FileCapture("C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquet test 1mess\envoye_1mess.pcapng")

capture.load_packets()
#https://stackoverflow.com/questions/41417235/pyshark-attribute-error-while-printing-dns-info
for i in range(len(capture)):
    try :
        #print("t'es ou")
        print()
        if capture[i].dns.qry_name :
            print("DNS Request from ip source : ")
            print(capture[i].dns.qry_nam)
            print("DNS Request from ip source : ", capture[i].ip.scr)
            print("DNS query name : ", capture[i].dns.qry_name)
    except :
        #ignore captures that aren't DNS Request
        continue
    try:
        if capture[i].dns.resp_name:
            print("DNS Respond from ip source : ", capture[i].ip.scr)
            print("DNS respond name")
    except :
        continue

#print(dir(capture))
#print(capture["tcp"])
#for i in range(len(capture)):
#    print("ici")
#    print(capture[i].dns.qry_name)

#print(capture[52])
#print(capture[52].dns.qry_name)
#print(len(capture))
#print(capture[0])
#print(capture.dns.field_names)