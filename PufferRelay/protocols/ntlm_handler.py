from PufferRelay.core_imports import pyshark
from PufferRelay.core_imports import binascii
from PufferRelay.core_imports import logging


def process_ntlm(pcap_file):
    print("ENTERING NTLM HANDLER")  # Simple print to verify function entry
    """
    Extracts NTLM authentication hashes from network captures.
    
    Args:
        pcap_file (str): Path to the pcap file
        
    Returns:
        list: List of tuples containing (source_ip, destination_ip, username, ntlm_hash)
    """
    logging.info(f"Starting NTLM processing for file: {pcap_file}")
    
    try:
        # Try with a basic filter first
        capture = pyshark.FileCapture(pcap_file, display_filter="ntlmssp && ntlmssp.messagetype == 3")
        logging.info("Opened PCAP file with NTLM filter")
        
        extracted_data = []
        packet_count = 0
        
        for packet in capture:
            packet_count += 1
            try:
                # Print the packet to see what we're getting
                #print(f"Packet {packet_count}: {packet}")
                
                # Extract source and destination IPs
                src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
                
                if src_ip == "N/A" or dst_ip == "N/A":
                    continue
                
                # Initialize NTLM fields
                username = "N/A"
                ntlm_hash = "N/A"
                print(packet.smb2)
                if hasattr(packet, 'smb2'):
                    #print(f"Found NTLM packet: {packet.smb2}")
                    
                    if hasattr(packet.smb2, 'ntlmssp_ntlmv2_response_dns_computer_name'):
                        username = packet.smb2.ntlmssp_ntlmv2_response_dns_computer_name
                        print(f"Found username: {username}")
                        
                    if hasattr(packet.smb2, 'ntlmssp_ntlmv2_response'):
                        ntlm_hash = packet.smb2.ntlmssp_ntlmv2_response
                        print(f"Found NTLM hash: {ntlm_hash}")
                
                # Only add to extracted data if we have both username and hash
                if username != "N/A" and ntlm_hash != "N/A":
                    entry = (src_ip, dst_ip, username, ntlm_hash)
                    print(f"Adding NTLM entry: {entry}")
                    extracted_data.append(entry)
            
            except AttributeError as e:
                print(f"Skipping packet due to missing attributes: {str(e)}")
                continue
        
        print(f"Processed {packet_count} packets, found {len(extracted_data)} NTLM entries")
        return extracted_data
        
    except Exception as e:
        print(f"Error processing NTLM packets: {str(e)}")
        return []
    finally:
        if 'capture' in locals():
            capture.close()