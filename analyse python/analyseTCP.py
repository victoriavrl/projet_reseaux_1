import pyshark

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

filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\\appel_audio\\recois_appel_audio_4G\paquet2.pcapng"

print(get_TCP_dest(filepath))