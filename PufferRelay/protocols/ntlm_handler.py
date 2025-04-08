from PufferRelay.core_imports import pyshark
from PufferRelay.core_imports import binascii


def process_ntlm(pcap_file):
    """
    Extracts NTLM authentication hashes from network captures.
    
    Args:
        pcap_file (str): Path to the pcap file
        
    Returns:
        list: List of tuples containing (source_ip, destination_ip, username, ntlm_hash)
    """
    # Filter for NTLM authentication packets
    capture = pyshark.FileCapture(pcap_file, display_filter="ntlmssp")
    extracted_data = []
    
    for packet in capture:
        try:
            # Extract source and destination IPs
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
            
            # Initialize NTLM fields
            username = "N/A"
            ntlm_hash = "N/A"
            
            if hasattr(packet, 'ntlmssp'):
                # Check for NTLM type 3 message (contains the hash)
                if hasattr(packet.ntlmssp, 'ntlmssp_messagetype') and packet.ntlmssp.ntlmssp_messagetype == '3':
                    # Extract username
                    if hasattr(packet.ntlmssp, 'ntlmssp_username'):
                        username = packet.ntlmssp.ntlmssp_username
                    
                    # Extract NTLM hash
                    if hasattr(packet.ntlmssp, 'ntlmssp_ntresponse'):
                        # The NTLM response is in hex format, we'll store it as is
                        ntlm_hash = packet.ntlmssp.ntlmssp_ntresponse
                    
                    # Only add to extracted data if we have both username and hash
                    if username != "N/A" and ntlm_hash != "N/A":
                        extracted_data.append((src_ip, dst_ip, username, ntlm_hash))
        
        except AttributeError:
            continue  # Skip packets that don't have the expected attributes
    
    capture.close()
    return extracted_data