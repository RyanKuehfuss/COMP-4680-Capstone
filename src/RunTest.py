from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import time

ipSender = ''
ipReceiver = ''

# 0,tcp,http,S1,220,29200,0,normal
def TestCase1():
    # SYN
    packet1 = IP(src=ipSender, dst=ipReceiver) / TCP(sport=5000, dport=80, flags='S') / b"\x00" * 110
    
    # SYN-ACK
    packet2 = IP(src=ipReceiver, dst=ipSender) / TCP(sport=80, dport=5000, flags='SA') / b"\x00" * 29200
    
    # ACK
    packet3 = IP(src=ipSender, dst=ipReceiver) / TCP(sport=5000, dport=80, flags='A') / b"\x00" * 110

    send(packet1)
    send(packet2)
    send(packet3)


# 0,tcp,http,REJ,0,0,0,anomaly
def TestCase2():
    packet = IP(src=ipSender, dst=ipReceiver) / TCP(sport=5000, dport=80, flags='R', seq=800)
    
    send(packet)


# 0,udp,private,SF,54,51,0,normal
def TestCase3():
    packet1 = IP(src=ipSender, dst=ipReceiver) / UDP(sport=5000, dport=73) / b"\x00" * 54
    packet2 = IP(src=ipSender, dst=ipReceiver) / UDP(sport=73, dport=5000) / b"\x00" * 51
    
    send(packet1)
    send(packet2)


# 0,udp,private,SF,105,146,0,anomaly
def TestCase4():
    packet1 = IP(src=ipSender, dst=ipReceiver) / UDP(sport=5000, dport=73) / b"\x00" * 105
    packet2 = IP(src=ipSender, dst=ipReceiver) / UDP(sport=73, dport=5000) / b"\x00" * 146
    
    send(packet1)
    send(packet2)


# 0,icmp,eco_i,SF,40008,0,0,normal
def TestCase5():
    packet = IP(src=ipSender, dst=ipReceiver) / ICMP(type=8, code=0) / b"\x00" * 40008
    
    send(packet)


# 0,icmp,ecr_i,SF,520,0,0,anomaly
def TestCase6():
    packet = IP(src=ipSender, dst=ipReceiver) / ICMP(type=0, code=0) / b"\x00" * 520
    
    send(packet)
    

if __name__ == '__main__':
    print('Running TCP test cases...')

    TestCase1()
    time.sleep(1)
    TestCase2()

    print('Finished TCP test cases.')
    time.sleep(1)
    print('Running UDP test cases...')

    TestCase3()
    time.sleep(1)
    TestCase4()

    print('Finished UDP test cases.')
    time.sleep(1)
    print('Running ICMP test cases...')

    TestCase5()
    time.sleep(1)
    TestCase6()

    print('Finished ICMP test cases.')
    print('All test cases completed.')