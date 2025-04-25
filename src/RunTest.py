from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import time

ipSender = ''
ipReceiver = ''


# 0, tcp, http, S1, 220, 29200, 0, normal
def TestCase1():
    # SYN
    packet1 = IP(src=ipSender, dst=ipReceiver) / TCP(sport=80, dport=80, flags='S') / Raw(b'\x00' * 110)
    
    # SYN-ACK
    packet2 = IP(src=ipReceiver, dst=ipSender) / TCP(sport=80, dport=80, flags='SA') / Raw(b'\x00' * 29200)
    
    # ACK
    packet3 = IP(src=ipSender, dst=ipReceiver) / TCP(sport=80, dport=80, flags='A') / Raw(b'\x00' * 110)

    send(packet1)
    send(packet2)
    send(packet3)


# 0, tcp, http, REJ, 0, 0, 0, anomaly
def TestCase2():
    packet = IP(src=ipReceiver, dst=ipSender) / TCP(sport=73, dport=73, flags='R', seq=800)
    
    send(packet,count=1)


# 0, udp, private, SF, 54, 51, 0, normal
def TestCase3():
    packet1 = IP(src=ipSender, dst=ipReceiver) / UDP(sport=73, dport=73) / Raw(b'\x00' * 54)
    packet2 = IP(src=ipReceiver, dst=ipSender) / UDP(sport=73, dport=73) / Raw(b'\x00' * 51)
    
    send(packet1,count=1)
    send(packet2,count=1)


# 0, udp, private, SF, 105, 146, 0, anomaly
def TestCase4():
    packet1 = IP(src=ipSender, dst=ipReceiver) / UDP(sport=73, dport=73) / Raw(b'\x00' * 105)
    packet2 = IP(src=ipReceiver, dst=ipSender) / UDP(sport=73, dport=73) / Raw(b'\x00' * 146)
    
    send(packet1,count=1)
    send(packet2,count=1)


# 0, icmp, ecr_i, SF, 30, 0, 0, normal
def TestCase5():
    packet = IP(src=ipSender, dst=ipReceiver) / ICMP(type=0, code=0) / Raw(b'\x00' * 30)
    
    send(packet,count=1)


# 0, icmp, ecr_i, SF, 520, 0, 0, anomaly
def TestCase6():
    packet = IP(src=ipSender, dst=ipReceiver) / ICMP(type=0, code=0) / Raw(b'\x00' * 520)
    
    send(packet,count=1)
    

if __name__ == '__main__':
    
    testCaseNumber = int(input('Please enter the test case number: '))

    print(f'Running test case {testCaseNumber}...')
    if testCaseNumber == 1:
        TestCase1()
    elif testCaseNumber == 2:
        TestCase2()
    elif testCaseNumber == 3:
        TestCase3()
    elif testCaseNumber == 4:
        TestCase4()
    elif testCaseNumber == 5:
        TestCase5()
    else:
        TestCase6()
    time.sleep(1)
    print(f'Finished running test case {testCaseNumber}.')
