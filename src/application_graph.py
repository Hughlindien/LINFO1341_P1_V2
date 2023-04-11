import pyshark
import matplotlib.pyplot as plt

# Capture des données
cap1 = pyshark.FileCapture('../Captures/test_2_v2.pcapng', only_summaries=False) # fichiers
cap2 = pyshark.FileCapture('../Captures/test_3_v2.pcapng', only_summaries=False) # vidéos
cap3 = pyshark.FileCapture('../Captures/test_4_v2.pcapng', only_summaries=False) # vocal

# Temps de début pour chaque capture
start_time1 = 0
start_time2 = 0
start_time3 = 0
#start_time4 = 0
#time_to_compute = 100

# Initialisation des variables
data1 = {}
data2 = {}
data3 = {}
#data4 = {}


# Capture des données pour chaque capture
for packet in cap1:
    #if float(packet.frame_info.time_relative) >= start_time1 and float(packet.frame_info.time_relative) <= (start_time1 + time_to_compute):
    time = int(float(packet.frame_info.time_relative) - start_time1)
    if time in data1:
        data1[time] += 1
    else:
        data1[time] = 1
    #elif float(packet.frame_info.time_relative) > (start_time1 + time_to_compute):
    #    break


for packet in cap2:
    #if float(packet.frame_info.time_relative) >= start_time2 and float(packet.frame_info.time_relative) <= (start_time2 + time_to_compute):
    time = int(float(packet.frame_info.time_relative) - start_time2)
    if time in data2:
        data2[time] += 1
    else:
        data2[time] = 1
    #elif float(packet.frame_info.time_relative) > (start_time2 + time_to_compute):
    #    break


for packet in cap3:
    #if float(packet.frame_info.time_relative) >= start_time3 and float(packet.frame_info.time_relative) <= (start_time3 + time_to_compute):
    time = int(float(packet.frame_info.time_relative) - start_time3)
    if time in data3:
        data3[time] += 1
    else:
        data3[time] = 1
    #elif float(packet.frame_info.time_relative) > (start_time3 + time_to_compute):
    #    break

#for packet in cap4:
    #if float(packet.frame_info.time_relative) >= start_time4 and float(packet.frame_info.time_relative) <= (start_time4 + time_to_compute):
    #time = int(float(packet.frame_info.time_relative) - start_time4)
    #if time in data4:
    #    data4[time] += 1
    #else:
    #    data4[time] = 1
    #elif float(packet.frame_info.time_relative) > (start_time4 + time_to_compute):
    #    break

# Tracer des graphes
fig, ax = plt.subplots()
plt.rcParams.update({'font.size': 16}) # Mise à jour de la taille de police
plt.rc('xtick', labelsize=14)
plt.rc('ytick', labelsize=14)
plt.title("Volume de données échangées en fonction du temps lors des différentes captures")
plt.xlabel('Temps [sec]')
plt.ylabel('Nombre de paquets par seconde [#/sec]')
plt.plot(list(data1.keys()), list(data1.values()), label='Messages + Fichiers', color='crimson')
plt.plot(list(data3.keys()), list(data3.values()), label='Appel Audio', color='green')
plt.plot(list(data2.keys()), list(data2.values()), label='Appel Vidéo', color='blue')
#plt.plot(list(data4.keys()), list(data4.values()), label='Capture 4', color='darkviolet')
plt.legend()
plt.show()
