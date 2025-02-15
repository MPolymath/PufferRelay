from PufferRelay.core_imports import pyshark

#LDAP extract data
def process_ldap(pcap_file):
    """Extracts LDAP bind request name and simple fields from a pcap file."""
    
    # Open the capture file with a filter for LDAP Bind Requests
    capture = pyshark.FileCapture(pcap_file, display_filter="ldap && ldap.protocolOp==bindRequest")
    capture.set_debug 
    extracted_data = []
    
    for packet in capture:
        try:
            # Extract source and destination IPs
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
            # Extract LDAP fields
            ldap_name = packet.ldap.get('ldap.name', 'N/A') if hasattr(packet, 'ldap') else "N/A"  # Get name
            ldap_simple = packet.ldap.get('ldap.simple', 'N/A') if hasattr(packet, 'ldap') else "N/A"  # Get simple
            extracted_data.append((src_ip, dst_ip, ldap_name, ldap_simple))
        
        except AttributeError:
            continue  # Skip packets that don't have the expected attributes

    capture.close()
    
    return extracted_data