import pyshark
import math

def get_TCP_dest(filepath):
    capture = pyshark.FileCapture(filepath)

    capture.load_packets()

    dest = []

    for p in capture:
        if hasattr(p, 'tcp'):
            try :
                ip = p.ip.dst
                isnot = True
                for e in dest :
                    if e == ip:
                        isnot= False
                        break
                if (isnot):
                    dest.append(ip)

                ip = p.ip.src
                isnot = True
                for e in dest:
                    if e == ip:
                        isnot = False
                        break
                if (isnot):
                    dest.append(ip)
            except:
                ip = p.ipv6.dst
                isnot = True
                for e in dest:
                    if e == ip:
                        isnot = False
                        break
                if (isnot):
                    dest.append(ip)

                ip = p.ipv6.src
                isnot = True
                for e in dest:
                    if e == ip:
                        isnot = False
                        break
                if (isnot):
                    dest.append(ip)
    return dest


#filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\mess\envoie_recois_mess_4G\paquet1.pcapng"

#filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\mess\envoie_recois_mess_ethernet\paquet1.pcapng"

#filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\mess\envoie_recois_mess_wifi\paquet1.pcapng"

#filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\mess\envoie_recois_mess_wifi_wifi\paquet1.pcapng"

#filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\\appel_audio\\recois_appel_audio_4G\paquet1.pcapng"

#filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\\appel_audio\\envoie_appel_audio_ethernet\paquet1.pcapng"

#print(get_TCP_dest(filepath))


def get_total_length_all_data(filepath):
    capture = pyshark.FileCapture(filepath)

    capture.load_packets()

    res = 0

    for p in capture:
        if hasattr(p, 'tcp'):
            try:
                if p.ip.dst != '52.159.49.199' and p.ip.src != '52.159.49.199':
                    continue

                res += math.ceil(len(p.tls.app_data) /3)
            except : #pas tls mais ack donc pas de .tls et leveut pas vu que pas des donnée envoyer par l'un des utilisateurs
                continue

    return res

#filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\load data\mess\paquet1.pcapng"
#filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\load data\mess\paquet2.pcapng"

#capture = pyshark.FileCapture(filepath)

#capture.load_packets()

#print(math.ceil(len(capture[1441].tls.app_data) /3))
#print(dir(capture[4].tls))

filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\load data\mess\paquet2.pcapng"

print(get_total_length_all_data(filepath))