from PufferRelay.core_imports import pyshark

#SMTP extract data
def process_smtp(pcap_file):
    """Extracts SMTP form data"""
    
    # Open the capture file with a filter for SMTP Requests
    capture = pyshark.FileCapture(pcap_file, display_filter="smtp.auth.password || smtp.auth.username")
    capture.set_debug 
    extracted_data = []

    for packet in capture:
        try:
            # Extract source and destination IPs
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
            # Extract SMTP fields
            smtp_user = packet.smtp.get('smtp.auth.username', 'N/A') if hasattr(packet, 'smtp') else "N/A"  # Get full URL
            smtp_password = packet.smtp.get('smtp.auth.password', 'N/A') if hasattr(packet, 'smtp') else "N/A"  # Get form content
            
            extracted_data.append((src_ip, dst_ip, smtp_user, smtp_password))
      
        except AttributeError:
            continue  # Skip packets that don't have the expected attributes

    capture.close()

    return extracted_data