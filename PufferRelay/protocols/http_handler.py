from PufferRelay.core_imports import pyshark
from PufferRelay.core_imports import urllib
from PufferRelay.core_imports import binascii

#HTTP extract data
def process_http(pcap_file):
    """Extracts HTTP form data"""
    
    # Open the capture file with a filter for LDAP Bind Requests
    capture = pyshark.FileCapture(pcap_file, display_filter="http && http.request.method==POST")
    capture.set_debug 
    extracted_data = []
    
    for packet in capture:
        try:
            # Extract source and destination IPs
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
            # Extract HTTP fields
            http_full_url_path = packet.http.get('http.host', 'N/A') + packet.http.get('http.request.uri', 'N/A') if hasattr(packet, 'http') else "N/A"  # Get full URL
            
            # Get form content with proper error handling
            http_form_content = "N/A"
            if hasattr(packet, 'http'):
                try:
                    file_data = packet.http.get('http.file_data', 'N/A')
                    if file_data != 'N/A':
                        # Remove colons and ensure even length
                        hex_data = file_data.replace(":", "")
                        if len(hex_data) % 2 == 0 and hex_data:  # Check for even length and non-empty
                            binary_data = binascii.unhexlify(hex_data)
                            decoded_data = binary_data.decode('utf-8')
                            http_form_content = urllib.parse.unquote(decoded_data)
                except (binascii.Error, UnicodeDecodeError, AttributeError):
                    http_form_content = "N/A"  # Return N/A if any conversion fails
            
            extracted_data.append((src_ip, dst_ip, http_full_url_path, http_form_content))
        
        except AttributeError:
            continue  # Skip packets that don't have the expected attributes
    
    capture.close()
    
    return extracted_data