from scapy.all import get_if_addr, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet
from Services import services, types

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

    #print("in group: ", len(packets))

    packets = reassemble_fragments(packets)

    #print("in group: ", len(packets))

    for packetSet in packets:
        packet = packetSet[0]
        packetTime = packetSet[1]
        

        if(packet.haslayer(IP)):
            ipPair = tuple(sorted([packet[IP].src, packet[IP].dst]))
            if packet.haslayer(TCP):
                #print("hereTCP")
                portPair = tuple(sorted([packet[TCP].sport, packet[TCP].dport]))
                connectionKey = ipPair + portPair + (packet[IP].proto,)
            elif packet.haslayer(UDP):
                print("hereUDP")
                portPair = tuple(sorted([packet[UDP].sport, packet[UDP].dport]))
                connectionKey = ipPair + portPair + (packet[IP].proto,)
            elif packet.haslayer(ICMP):
                print("hereICMP")
                connectionKey = ipPair + (packet[IP].proto,)
            else:
                connectionKey = 'null'

            if connectionKey not in connections:
                #print("hereCONN")
                connections[connectionKey] = {
                    'packets': [],
                    'sessionStart': packetTime,
                    'sessionDuration': 0
                }
            connections[connectionKey]['packets'].append(packet)
            connections[connectionKey]['sessionDuration'] = packetTime - connections[connectionKey]['sessionStart']

        else:
            print("packet doesnt have ip?")

    return connections


def ExtractFeatures(connections : dict)-> dict:
    features = {}
    for connection, stats in connections.items():
        if connection != 'null':
            #print("null here")
            #try:
            packets = stats['packets']
            if packets:
                #print("in packets")
                if connection not in features:
                    features[connection]={}

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

            #except Exception as e:
                #print(f'Error processing session: {e}')
    return features


def AggregateFeatures(packets : list)-> dict:
    
    #print("in agg: ", len(packets))
    connections = GroupPackets(packets)

    #print(connections)

    if connections:
        #print("entering extraction")
        return ExtractFeatures(connections)
    return None

def reassemble_fragments(packets):
    ip_fragments = {}
    reassembled = []

    for packetset in packets:
        pkt = packetset[0]
        if IP in pkt and pkt[IP].flags & 1 or pkt[IP].frag != 0:
            # Fragmented packet
            ident = (pkt[IP].src, pkt[IP].dst, pkt[IP].id, pkt[IP].proto)
            ip_fragments.setdefault(ident, []).append(pkt)
        else:
            # Not fragmented
            reassembled.append((pkt,packetset[1]))

    for frag_group in ip_fragments.values():
        base = assemble_fragment(frag_group)
        full_pkt = IP(bytes(base[0]))
        reassembled.append((full_pkt,base[1]))

    return reassembled

def assemble_fragment(fragments):
    # Sort fragments by fragment offset
    fragments.sort(key=lambda p: p[IP].frag)

    ts = max(frag.time for frag in fragments)

    # Take the first fragment as base
    base = fragments[0][IP]

    # Reassemble payload
    payload = b''
    for frag in fragments:
        ip = frag[IP]
        offset = ip.frag * 8
        data = bytes(ip.payload)
        payload = payload[:offset] + data + payload[offset + len(data):]

    # Remove fragmentation flags and offset
    base.flags = 0
    base.frag = 0
    base.len = len(base) + len(payload)  # update total length
    base.payload = Raw(payload)

    return (base,ts)