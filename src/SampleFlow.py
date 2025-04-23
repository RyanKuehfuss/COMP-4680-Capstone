import time
from scapy.all import sniff

# Store packets temporarily
captured_packets = []

# Define the aggregation window (e.g., 5 seconds)
aggregation_window = 5  # seconds

# Packet capture callback
def packet_callback(packet):
    captured_packets.append(packet)

# Function to aggregate and extract features
def aggregate_features(packets):
    # Step 1: Group packets by connection (src_ip, dst_ip, src_port, dst_port, protocol)
    connections = {}  # Use a dictionary to track connections
    
    for packet in packets:
        connection_key = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport, packet[IP].proto)
        
        if connection_key not in connections:
            connections[connection_key] = {
                'packets': 0,
                'bytes': 0,
                'start_time': time.time(),
                'end_time': 0
            }
        
        connections[connection_key]['packets'] += 1
        connections[connection_key]['bytes'] += len(packet)
        connections[connection_key]['end_time'] = time.time()

    # Step 2: Extract features from each connection
    features = []
    for conn, stats in connections.items():
        duration = stats['end_time'] - stats['start_time']
        feature = {
            'src_ip': conn[0],
            'dst_ip': conn[1],
            'src_port': conn[2],
            'dst_port': conn[3],
            'protocol': conn[4],
            'packet_count': stats['packets'],
            'byte_count': stats['bytes'],
            'duration': duration,
        }
        features.append(feature)
    
    return features

# Function to classify aggregated features using the trained model
def classify_traffic(features, model):
    for feature in features:
        # Prepare the feature vector for the model (this will depend on your model's requirements)
        feature_vector = prepare_feature_vector(feature)
        
        # Feed the feature vector into the trained model
        prediction = model.predict([feature_vector])  # Assuming `model` is a trained classifier
        
        # If malicious (anomalous), take action
        if prediction == 1:  # Assuming 1 means attack, 0 means normal
            log_attack(feature)
            block_ip(feature['src_ip'])

# Example of packet capturing in real-time
def capture_packets():
    print("Capturing packets...")
    sniff(prn=packet_callback, store=0, timeout=aggregation_window)

# Run the system
while True:
    # Capture packets in real-time
    capture_packets()
    
    # Aggregate features every 5 seconds
    features = aggregate_features(captured_packets)
    
    # Use a trained model to classify the aggregated features
    classify_traffic(features, trained_model)  # Replace `trained_model` with your actual model
    
    # Clear captured packets for the next cycle
    captured_packets.clear()
