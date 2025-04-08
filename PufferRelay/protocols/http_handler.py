from PufferRelay.core_imports import pyshark
from PufferRelay.core_imports import urllib
from PufferRelay.core_imports import binascii
from PufferRelay.core_imports import base64

#HTTP extract data
def process_http(pcap_file):
    """Extracts HTTP form data and basic authentication credentials"""
    
    # Open the capture file with filters for HTTP POST and basic auth
    capture = pyshark.FileCapture(pcap_file, display_filter="http && (http.request.method==POST || http.authorization)")
    capture.set_debug 
    extracted_data = []
    
    for packet in capture:
        try:
            # Extract source and destination IPs
            src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
            
            # Extract HTTP fields
            http_full_url_path = packet.http.get('http.host', 'N/A') + packet.http.get('http.request.uri', 'N/A') if hasattr(packet, 'http') else "N/A"
            
            # Initialize auth and form content
            http_auth_username = "N/A"
            http_auth_password = "N/A"
            http_form_content = "N/A"
            
            if hasattr(packet, 'http'):
                # Check for basic authentication
                auth_header = packet.http.get('http.authorization', 'N/A')
                if auth_header != 'N/A' and 'Basic' in auth_header:
                    try:
                        # Extract and decode base64 credentials
                        auth_string = auth_header.split('Basic ')[1]
                        decoded_auth = base64.b64decode(auth_string).decode('utf-8')
                        username, password = decoded_auth.split(':', 1)
                        http_auth_username = username
                        http_auth_password = password
                    except (IndexError, UnicodeDecodeError, base64.binascii.Error):
                        pass
                
                # Get form content with proper error handling
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
            
            # Only add to extracted data if we have meaningful information
            if (http_auth_username != "N/A" and http_auth_password != "N/A") or http_form_content != "N/A":
                extracted_data.append((src_ip, dst_ip, http_full_url_path, http_form_content, http_auth_username, http_auth_password))
        
        except AttributeError:
            continue  # Skip packets that don't have the expected attributes
    
    capture.close()
    
    return extracted_data