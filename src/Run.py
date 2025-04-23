from FeatureExtraction import AggregateFeatures
from scapy.all import sniff
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
logging.basicConfig(filename=os.path.join(PATH, 'logs', LOGTIME + '-dgb.txt'), format='%(levelname)s: %(message)s', level=logging.debug)
logging.info('Started Logging Successfully.')


capturedPackets = []
aggregationWindowTime = 5
model = load('GradientBoostingFile.pkl')


def SavePacket(packet):
    capturedPackets.append([packet, time.time()])


def CapturePackets():
    print('Capturing packets...')
    # Sniffer for packets need to make eth0 environment variable
    # or something like that if we want this to be easily modular
    # to other systems
    sniff(prn=SavePacket, store=0, timeout=aggregationWindowTime, iface="eth0")
    

def ClassifyTraffic(features : dict):
    for connection in features:
        featureList = []
        for key, value in connection.items():
            featureList.append(value)

        prediction = model.predict(featureList)

        if prediction == 1:
            logging.info(f'A Suspicious connection has been found: {connection} | PACKET INFORMATION : {features[connection]}')


while True:
    CapturePackets()

    features = AggregateFeatures(capturedPackets)

    if features:
        ClassifyTraffic()

    capturedPackets.clear()
