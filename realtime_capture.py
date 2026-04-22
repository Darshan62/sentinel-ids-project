from scapy.all import sniff

def extract_features(packet):
    features = {}

    try:
        features["Packet Length"] = len(packet)
        features["Protocol"] = packet.proto if hasattr(packet, "proto") else 0

        if packet.haslayer("IP"):
            features["Src IP"] = packet["IP"].src
            features["Dst IP"] = packet["IP"].dst
        else:
            features["Src IP"] = "0"
            features["Dst IP"] = "0"

        if packet.haslayer("TCP"):
            features["Src Port"] = packet["TCP"].sport
            features["Dst Port"] = packet["TCP"].dport
        else:
            features["Src Port"] = 0
            features["Dst Port"] = 0

    except:
        return None

    return features

sniff_running = False

def start_sniffing(callback, packet_count=20):
    global sniff_running
    sniff_running = True
    def stop_filter(p):
        return not sniff_running
    sniff(prn=callback, count=packet_count, stop_filter=stop_filter)

def stop_sniffing():
    global sniff_running
    sniff_running = False