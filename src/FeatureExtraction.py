from scapy.all import get_if_addr, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet
from Services import services, types

myIp = get_if_addr('eth0')


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
    elif packet.haslayer(ICMP):
        type = (packet[ICMP].type, packet[ICMP].code)
        return types.get(type, 'other')
    return 'other'


def GetFlag(packets: list)-> str:
    packet = packets[-1]
    previousPacket = None
    if len(packets) > 1:
        previousPacket = packets[-2]

    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        
        if flags == 'R':
            if previousPacket and packet[TCP].seq == previousPacket[TCP].seq:
                return 'RSTR'
            elif packet[TCP].seq == 0:
                return 'RSTOS0'
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
                if packet.haslayer(Raw):
                    srcBytes += len(packet[Raw].load)
    return srcBytes


def GetDSTBytes(packets: list):
    dstBytes = 0
    for packet in packets:
        if packet.haslayer(IP):
            if packet[IP].src == myIp:
                if packet.haslayer(Raw):
                    dstBytes += len(packet[Raw].load)
    return dstBytes


def IsLandAttack(packets: list)-> int:
    for packet in packets:
        if packet.haslayer(IP):
            if packet[IP].src == packet[IP].dst:
                return 1
    return 0


def ReassembleFragments(packets: list)-> list:
    ipFragments = {}
    reassembledPackets = []

    for packetSet in packets:
        packet = packetSet[0]
        if IP in packet and packet[IP].flags & 1 or packet[IP].frag != 0:
            ident = (packet[IP].src, packet[IP].dst, packet[IP].id, packet[IP].proto)
            ipFragments.setdefault(ident, []).append(packet)
        else:
            reassembledPackets.append((packet, packetSet[1]))

    for fragmentGroup in ipFragments.values():
        base = AssembleFragment(fragmentGroup)
        fullPacket = IP(bytes(base[0]))
        reassembledPackets.append((fullPacket,base[1]))

    return reassembledPackets


def AssembleFragment(fragments: list)-> tuple:
    fragments.sort(key=lambda packet: packet[IP].frag)
    timeStamp = max(frag.time for frag in fragments)
    assembledPacket = fragments[0][IP]

    payload = b''
    for fragment in fragments:
        ip = fragment[IP]
        offset = ip.frag * 8
        data = bytes(ip.payload)
        payload = payload[:offset] + data + payload[offset + len(data):]

    assembledPacket.flags = 0
    assembledPacket.frag = 0
    assembledPacket.len = len(assembledPacket) + len(payload)
    assembledPacket.payload = Raw(payload)

    return (assembledPacket, timeStamp)


def GroupPackets(packets : list)-> dict:
    connections = {}
    packets = ReassembleFragments(packets)

    for packetSet in packets:
        packet = packetSet[0]
        packetTime = packetSet[1]
        

        if(packet.haslayer(IP)):
            ipPair = tuple(sorted([packet[IP].src, packet[IP].dst]))
            if packet.haslayer(TCP):
                portPair = tuple(sorted([packet[TCP].sport, packet[TCP].dport]))
                connectionKey = ipPair + portPair + (packet[IP].proto,)
            elif packet.haslayer(UDP):
                portPair = tuple(sorted([packet[UDP].sport, packet[UDP].dport]))
                connectionKey = ipPair + portPair + (packet[IP].proto,)
            elif packet.haslayer(ICMP):
                connectionKey = ipPair + (packet[IP].proto,)
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
        else:
            print('Packet doesn\'t have an IP layer.')
    return connections


def ExtractFeatures(connections : dict)-> dict:
    features = {}
    for connection, stats in connections.items():
        if connection != 'null':
            try:
                packets = stats['packets']
                if packets:
                    if connection not in features:
                        features[connection] = {}

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
    return features


def AggregateFeatures(packets : list)-> dict:
    connections = GroupPackets(packets)

    if connections:
        return ExtractFeatures(connections)
    return None
