from FeatureExtraction import AggregateFeatures
from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.packet import Packet
import time
from joblib import load
import logging
import os
import sys
import pandas as pd


model = load('GradientBoostingFile.pkl')

csvFile = "trimmed_test.csv"

df = pd.read_csv(csvFile)
X = df.iloc[:, :-1].values
y = df.iloc[:, -1].values

for line in X: 
    pred = model.predict([line])
    if (pred == 1):
        print(line)


