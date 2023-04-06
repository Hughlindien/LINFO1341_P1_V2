import subprocess
import re
import pyshark
import OpenSSL.crypto

#cap= pyshark.FileCapture('../captures/test1v2.pcapng', only_summaries=False) # messages
#cap= pyshark.FileCapture('../captures/test_2_v2.pcapng', only_summaries=False) # fichiers
#cap= pyshark.FileCapture('../captures/test2v2.pcapng', only_summaries=False)
#cap= pyshark.FileCapture('../captures/test_3_v2.pcapng', only_summaries=False) # vidéos
#cap= pyshark.FileCapture('../captures/test3v2.pcapng', only_summaries=False)
#cap= pyshark.FileCapture('../captures/test_4_v2.pcapng', only_summaries=False) # vocal
cap= pyshark.FileCapture('../captures/test4v2.pcapng', only_summaries=False)


def add_dic(dico, elem):
    if dico.get(elem):
        dico[elem] += 1
    else:
        dico[elem] = 1
    return

def add_dico_set(dico, elem, to_add):
    if dico.get(elem):
        dico[elem].add(to_add)
    else:
        dico[elem] = set()
        dico[elem].add(to_add)
    return

trans_dico = dict()
version_dic = dict()
proto = dict()
cert = dict()
crypto = dict()
ex_key = dict()

for pkt in cap:
    for i in pkt.layers:
        if i.layer_name == 'tls':
            tls_layer = pkt[i.layer_name]
            add_dic(trans_dico, pkt.transport_layer)

            if hasattr(tls_layer, 'extension_psk_ke_mode'):
                add_dic(ex_key, tls_layer.extension_psk_ke_mode.showname_value)

            if hasattr(tls_layer, 'handshake_ciphersuite'):
                add_dic(crypto, tls_layer.handshake_ciphersuite.showname_value)

            if hasattr(tls_layer, 'app_data_proto'):
                add_dic(proto, tls_layer.app_data_proto.showname_value)

            if hasattr(tls_layer, 'record_version'):
                add_dic(version_dic, tls_layer.record_version.showname_value)


print("versions tls : ", version_dic)
print("Application Data Protocol : ", proto)
print("Protocoles de transport sécurisés par tls : ", trans_dico)
print("Algorithmes de cryptage utilisés : ", crypto)
print("Protocol d'échange de clés : ", ex_key)