import pyshark
import math

def get_UDP_dest(filepath):
    capture = pyshark.FileCapture(filepath)

    capture.load_packets()

    dest = []

    for p in capture:
        if hasattr(p, 'udp'):
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

#filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\\appel_audio\\recois_appel_audio_4G\paquet5.pcapng"

#filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\\appel_audio\\envoie_appel_audio_ethernet\paquet4.pcapng"

#print(get_UDP_dest(filepath))


def get_total_length_all_data(filepath):
    capture = pyshark.FileCapture(filepath)

    capture.load_packets()

    res = 0

    for p in capture:
        if hasattr(p, 'udp'):
            try:
                # Adresse ip Victoria pour ce sénario (appel_audio et appel_video) : 192.168.1.50 (veut pas des autres paquets car pas des info d'un utilisateur à envoyer à un autre)
                if p.ip.dst != '192.168.1.50' and p.ip.src != '192.168.1.50':
                    continue
                #n'est pas du data d'un utilisateur à envoyé à un autre
                if 'mdns' in p or 'stun' in p or 'rtcp' in p or 'icmp' in p:
                    continue

                res += math.ceil(len(p.udp.payload) /3)
            except :
                continue

    return res

#filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\load data\\appel_audio\paquet1.pcapng"

#capture = pyshark.FileCapture(filepath)

#capture.load_packets()

#print(capture[116])
#print(dir(capture[116]))
#print(math.ceil(len(capture[117].udp.payload) /3))
#print("int(capture[116].length) : ", int(capture[116].length))
#print("int(capture[116].udp.length) : ", int(capture[116].udp.length))
#print(dir(capture[116].udp.payload))

#filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\load data\\appel_audio\paquet2.pcapng"

#filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\load data\\appel_video\paquet2.pcapng"

filepath = "C:\\Users\delph\OneDrive\Documents\\UCL\B3Q2\LINFO1341 - Computer networks  information transfer\Projet\projet_reseaux_1\paquets\load data\\appel_audio_video\paquet2.pcapng"

print(get_total_length_all_data(filepath))