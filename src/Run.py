from FeatureExtraction import AggregateFeatures
from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.packet import Packet
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
aggregationWindowTime = 15
model = load('GradientBoostingFile.pkl')


def SavePacket(packet : Packet):
    if packet.haslayer(IP):
        if (packet[IP].src == '192.168.0.201' and packet[IP].dst == '172.25.237.199') or (packet[IP].src == '172.25.237.199' and packet[IP].dst == '192.168.0.201'):
            capturedPackets.append([packet, time.time()])


def CapturePackets():
    print('Capturing packets...')
    sniff(prn=SavePacket, store=0, timeout=aggregationWindowTime, iface='eth0')
    

def ClassifyTraffic(features : dict):
    for connection, innerDict in features.items():
        featureList = []
        for _, value in innerDict.items():
            featureList.append(value)

        prediction = model.predict([featureList])

        if prediction == 1:
            logging.info(f'A Suspicious connection has been found: {connection} | PACKET INFORMATION : {features[connection]}')


while True:
    CapturePackets()

    features = AggregateFeatures(capturedPackets)

    if features:
        ClassifyTraffic(features)

    capturedPackets.clear()
