from PufferRelay.core_imports import pyshark
from PufferRelay.core_imports import defaultdict

#TELNET extract data
def process_telnet(pcap_file):
    """Extracts TELNET form data"""
    conversations = defaultdict(str)
    # Open the capture file with a filter for TELNET Requests
    capture = pyshark.FileCapture(pcap_file, display_filter="telnet && (telnet.data)")
    capture.set_debug 
    
    for packet in capture:
        try:
            # Extract source and destination IPs
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
            # Extract Telnet fields
            telnet_data = packet.telnet.get('telnet.data')
            key = (src_ip, dst_ip)
            conversations[key] += telnet_data
        except AttributeError:
            continue  # Skip packets that don't have the expected attributes

    capture.close()
    
    # Convert the dict to a list of tuples
    return [(src, dst, data) for (src, dst), data in conversations.items()]