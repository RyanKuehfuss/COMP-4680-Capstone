from FeatureExtraction import AggregateFeatures
from scapy.all import sniff, IP, Packet
import time
from joblib import load
import logging
import os
import sys

PATH = os.path.dirname(os.path.abspath(sys.argv[0]))
os.chdir(PATH)

if not os.path.exists(os.path.join(PATH, 'logs')):
    os.mkdir(os.path.join(PATH, 'logs'))

LOGTIME = time.asctime().replace(' ', '_').replace(':', '-')
logging.basicConfig(filename=os.path.join(PATH, 'logs', LOGTIME + '-dgb.txt'), format='%(levelname)s: %(message)s', level=logging.DEBUG)
logging.info('Started Logging Successfully.')


capturedPackets = []
aggregationWindowTime = 10
model = load('GradientBoostingFile.pkl')



def SavePacket(packet : Packet):
    if packet.haslayer(IP):
        if (packet[IP].src == '192.168.0.201' and packet[IP].dst == '172.25.237.199') or (packet[IP].src == '172.25.237.199' and packet[IP].dst == '192.168.0.201'):
            #print(packet[IP].src, packet[IP].dst)
            capturedPackets.append([packet, time.time()])



def CapturePackets():
    print('Capturing packets...')
    # Sniffer for packets need to make eth0 environment variable
    # or something like that if we want this to be easily modular
    # to other systems
    allowed_ips = ["192.168.0.201", "172.25.237.199"]
    sniff(
    filter=f"ip src {allowed_ips[0]} or ip src {allowed_ips[1]}",
    prn=SavePacket,
    store=0,  # Don't store packets in memory, just process them
    timeout=aggregationWindowTime,
    iface="eth0"
)
    #sniff(filter=filter_str, prn=SavePacket, store=0, timeout=aggregationWindowTime, iface="eth0")
    

def ClassifyTraffic(features : dict):
    for connection,innerDict in features.items():
        print(features)
        featureList = []
        for key, value in innerDict.items():
            featureList.append(value)

        prediction = model.predict([featureList])

        if prediction == 1:
            print("Found Anomaly")
            logging.info(f'A Suspicious connection has been found: {connection} | PACKET INFORMATION : {features[connection]}')
        else:
             print("Found Normal")


#while True:
CapturePackets()

#print(len(capturedPackets))
features = AggregateFeatures(capturedPackets)

if features:
    #print("here2")
    ClassifyTraffic(features)

capturedPackets.clear()
