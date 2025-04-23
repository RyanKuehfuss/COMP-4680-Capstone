from scapy.all import get_if_addr
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet
from services import services

# NEED TO MAKE THIS CHANGE WITH THE SNIFFER
myIp = get_if_addr("eth0")


def GetProtocol(packet: Packet)-> str:
    if packet.haslayer(TCP):
        return 'tcp'
    elif packet.haslayer(UDP):
        return 'udp'
    elif packet.haslayer(ICMP):
        return 'icmp'
    else:
        return 'none'


def GetService(packet: Packet)-> str:
    if packet.haslayer(TCP):
        port = packet[TCP].dport
        return services.get(port, 'other')
    elif packet.haslayer(UDP):
        port = packet[UDP].dport
        return services.get(port, 'other')
    return 'other'


def GetFlag(packets: list)-> str:
    packet = packets[-1]
    if len(packets) > 1:
        previousPacket = packets[-2]

    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        
        if flags == 'R':
            if previousPacket and packet[TCP].seq == previousPacket[TCP].seq:
                return 'RSTR'
            elif packet[TCP].seq == 0:
                return 'RSTOS0'
            # NEED TO DO THIS FLAG IN THE RUN TEST FILE
            elif packet[IP].src != myIp:
                return 'RSTO'
            return 'REJ'
        else:
            senderFlags = []
            receiverFlags = []
            for packet in packets:
                if packet[IP].src == myIp:
                    receiverFlags.append(packet[TCP].flags)    
                else:
                    senderFlags.append(packet[TCP].flags)  

            # Sender sent SYN but no SYN-ACK or RST from receiver
            if any('S' in str(flag) for flag in senderFlags) and not any('SA' in str(flag) for flag in receiverFlags) and not any('R' in str(flag) for flag in receiverFlags):
                return 'S0'
            # Successfull TCP handshake, SYN, SYN-ACK, ACK
            elif any('S' in str(flag) for flag in senderFlags) and any('A' in str(flag) for flag in senderFlags) and any('SA' in str(flag) for flag in receiverFlags):
                return 'S1'
            # Sender sent FIN, receiver did not send FIN
            elif any('F' in str(flag) for flag in senderFlags) and not any('F' in str(flag) for flag in receiverFlags):
                return 'S2'
            # Sender did not send FIN, receiver did send FIN
            elif not any('F' in str(flag) for flag in senderFlags) and any('F' in str(flag) for flag in receiverFlags):
                return 'S3'
            # Full connection and normal FIN closure
            elif any('F' in str(flag) for flag in senderFlags) and any('F' in str(flag) for flag in receiverFlags):
                return 'SF'
            # Sender sent SYN then Immediately send FIN, No data transfer
            for i in range(len(packets) - 2):
                if 'S' in packets[i] and 'SA' in packets[i + 1] and ('F' in packets[i + 2] or 'R' in packets[i + 2]):
                    return 'SH'
            return 'OTH' 
    else:
        return 'SF'


def GetSRCBytes(packets: list)-> int:
    srcBytes = 0
    for packet in packets:
        if packet.haslayer(IP):
            if packet[IP].dst == myIp:
                srcBytes += len(packet.payload)
    return srcBytes


def GetDSTBytes(packets: list):
    dstBytes = 0
    for packet in packets:
        if packet.haslayer(IP):
            if packet[IP].src == myIp:
                dstBytes += len(packet.payload)
    return dstBytes


def IsLandAttack(packets: list)-> int:
    for packet in packets:
        if packet.haslayer(IP):
            if packet[IP].src == packet[IP].dst:
                return 1
    return 0


def GroupPackets(packets : list)-> dict:
    connections = {}

    for packetSet in packets:
        packet = packetSet[0]
        packetTime = packetSet[1]
        
        ipPair = tuple(sorted([packet[IP].src, packet[IP].dst]))
        if packet.haslayer(TCP):
            portPair = tuple(sorted([packet[TCP].sport, packet[TCP].dport]))
            connectionKey = ipPair + portPair + (packet[IP].proto)
        elif packet.haslayer(UDP):
            portPair = tuple(sorted([packet[UDP].sport, packet[UDP].dport]))
            connectionKey = ipPair + portPair + (packet[IP].proto)
        elif packet.haslayer(ICMP):
            connectionKey = ipPair + (packet[IP].proto)
        else:
            connectionKey = 'null'

        if connectionKey not in connections:
            connections[connectionKey] = {
                'packets': [],
                'sessionStart': packetTime,
                'sessionDuration': 0
            }
        connections[connectionKey]['packets'].append(packet)
        connections[connectionKey]['sessionDuration'] = packetTime - connections[connectionKey]['sessionStart']
    return connections


def ExtractFeatures(connections : dict)-> dict:
    features = {}
    for connection, stats in connections.items():
        if connection != 'null':
            try:
                packets = stats['packets']
                if packets:
                    # Session Duration
                    features[connection]['duration'] = stats['sessionDuration']

                    # Get Packet Protocol
                    features[connection]['protocol_type'] = GetProtocol(packets[0])

                    # Get packets service
                    features[connection]['service'] = GetService(packets[-1])

                    # Get packets flags
                    features[connection]['flag'] = GetFlag(packets)

                    # Get packets src bytes
                    features[connection]['src_bytes'] = GetSRCBytes(packets)

                    # Get packets dst bytes
                    features[connection]['dst_bytes'] = GetDSTBytes(packets)

                    # Get if land attack
                    features[connection]['land'] = IsLandAttack(packets)

            except Exception as e:
                print(f'Error processing session: {e}')


def AggregateFeatures(packets : list)-> dict:
    connections = GroupPackets(packets)

    if connections:
        return ExtractFeatures(connections)
    return None