import pyshark

# Ouverture de la trace
cap = pyshark.FileCapture('../Captures/vidéo.pcapng', only_summaries=False)

transport_protocol = set() # Stock le nom des protocols de transport utilisés
for pkt in cap:
    transport_name = pkt.transport_layer
    transport_protocol.add(transport_name)

print(transport_protocol)