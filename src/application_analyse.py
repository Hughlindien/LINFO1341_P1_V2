import pyshark

#cap= pyshark.FileCapture('../Captures/test1v2.pcapng', only_summaries=False) # messages
#cap= pyshark.FileCapture('../Captures/test_2_v2.pcapng', only_summaries=False) # fichiers
#cap= pyshark.FileCapture('../Captures/test2v2.pcapng', only_summaries=False)
#cap= pyshark.FileCapture('../Captures/test_3_v2.pcapng', only_summaries=False) # vidéos
cap= pyshark.FileCapture('../Captures/test3v2.pcapng', only_summaries=False)
#cap= pyshark.FileCapture('../Captures/test_4_v2.pcapng', only_summaries=False) # vocal


start_time_3 = 95
end_time_3 = 241
data_volume = 0
data_volume3 = 0
prev_time = start_time_3
cnt = 0

print("================Vidéo===================")
for pkt in cap:
    if float(pkt.frame_info.time_relative) >= start_time_3 and float(pkt.frame_info.time_relative) <= end_time_3:
        data_volume += 1
        curr_time = int(float(pkt.frame_info.time_relative))
        if curr_time - prev_time >= 60:
            print("Volume de paquets échangées par minute :", data_volume)
            data_volume3 += data_volume
            prev_time = curr_time
            data_volume = 0
            cnt += 1
        if end_time_3 - curr_time < 60:
            break
print("Volume moyen échangé par minute :", data_volume3/cnt)

print(" ")
print(" ")
cap4= pyshark.FileCapture('../Captures/test4v2.pcapng', only_summaries=False)
start_time_4 = 75
end_time_4 = 310
data_volume = 0
data_volume4 = 0
prev_time = start_time_4
cnt = 0
 
print("================Audio===================")
for pkt in cap4:
    if float(pkt.frame_info.time_relative) >= start_time_4 and float(pkt.frame_info.time_relative) <= end_time_4:
        data_volume += 1
        curr_time = int(float(pkt.frame_info.time_relative))
        if curr_time - prev_time >= 60:
            print("Volume de paquets échangées par minute :", data_volume)
            data_volume4 += data_volume
            prev_time = curr_time
            data_volume = 0
            cnt += 1
        if end_time_4 - curr_time < 60:
            break
print("Volume moyen échangé par minute :", data_volume4/cnt)