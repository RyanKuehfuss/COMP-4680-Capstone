from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP, Ether
import time

ipSender = ''
ipReceiver = ''

senderMAC = ''
receiverMAC = ''


# 0,tcp,http,S1,220,29200,0,normal
def TestCase1():
    # SYN
    packet1 = Ether(dst=receiverMAC)/ IP(src=ipSender, dst=ipReceiver) / TCP(sport=5000, dport=81, flags='S') / Raw(b'\x00' * 110)
    
    # SYN-ACK
    packet2 = Ether(dst=senderMAC)/IP(src=ipReceiver, dst=ipSender) / TCP(sport=81, dport=5000, flags='SA') / Raw(b'\x00' * 29200)
    
    # ACK
    packet3 = Ether(dst=receiverMAC)/IP(src=ipSender, dst=ipReceiver) / TCP(sport=5000, dport=81, flags='A') / Raw(b'\x00' * 110)

    send(packet1)
    send(packet2)
    send(packet3)


# 0,tcp,http,REJ,0,0,0,anomaly
def TestCase2():
    packet = Ether(dst=receiverMAC)/IP(src=ipSender, dst=ipReceiver) / TCP(sport=5000, dport=80, flags='R', seq=800)
    
    send(packet,count=1)


# 0,udp,private,SF,54,51,0,normal
def TestCase3():
    packet1 = Ether(dst=receiverMAC)/IP(src=ipSender, dst=ipReceiver) / UDP(sport=5000, dport=73) / Raw(b'\x00' * 54)
    packet2 = Ether(dst=senderMAC)/IP(src=ipReceiver, dst=ipSender) / UDP(sport=73, dport=5000) / Raw(b'\x00' * 51)
    
    send(packet1,count=1)
    send(packet2,count=1)


# 0,udp,private,SF,105,146,0,anomaly
def TestCase4():
    packet1 = Ether(dst=receiverMAC)/IP(src=ipSender, dst=ipReceiver) / UDP(sport=5000, dport=73) / Raw(b'\x00' * 105)
    packet2 = Ether(dst=senderMAC)/IP(src=ipReceiver, dst=ipSender) / UDP(sport=73, dport=5000) / Raw(b'\x00' * 146)
    
    send(packet1,count=1)
    send(packet2,count=1)


# 0,icmp,eco_i,SF,40008,0,0,normal
def TestCase5():
    packet = Ether(dst=receiverMAC)/IP(src=ipSender, dst=ipReceiver) / ICMP(type=8, code=0) / Raw(b'\x00' * 40008)
    
    send(packet,count=1)


# 0,icmp,ecr_i,SF,520,0,0,anomaly
def TestCase6():
    packet = Ether(dst=receiverMAC)/IP(src=ipSender, dst=ipReceiver) / ICMP(type=0, code=0) / Raw(b'\x00' * 520)
    
    send(packet,count=1)
    

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
