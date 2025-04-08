from PufferRelay.core_imports import pyshark
from PufferRelay.core_imports import urllib
from PufferRelay.core_imports import binascii
from PufferRelay.core_imports import base64
from PufferRelay.core_imports import re
from PufferRelay.core_imports import logging
from PufferRelay.core_imports import defaultdict

def clean_http_data(data):
    """
    Cleans HTTP data by removing line breaks and extra whitespace.
    
    Args:
        data (str): The HTTP data to clean
        
    Returns:
        str: Cleaned HTTP data
    """
    if data == "N/A":
        return data
    
    # Remove line breaks and replace with spaces
    data = data.replace('\r', ' ').replace('\n', ' ')
    
    # Replace multiple spaces with a single space
    data = re.sub(r'\s+', ' ', data)
    
    # Remove leading/trailing whitespace
    data = data.strip()
    
    return data

def decode_basic_auth(auth_header):
    """
    Decodes Basic Authentication credentials from base64.
    
    Args:
        auth_header (str): The Authorization header value
        
    Returns:
        tuple: (username, password) or (None, None) if decoding fails
    """
    try:
        if not auth_header or 'Basic ' not in auth_header:
            return None, None
            
        # Extract the base64 part
        auth_string = auth_header.split('Basic ')[1]
        
        # Decode base64
        decoded_auth = base64.b64decode(auth_string).decode('utf-8')
        
        # Split into username and password
        username, password = decoded_auth.split(':', 1)
        
        return clean_http_data(username), clean_http_data(password)
    except (IndexError, UnicodeDecodeError, base64.binascii.Error) as e:
        logging.error(f"Error decoding Basic Auth: {str(e)}")
        return None, None

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
            
            # Skip if we don't have valid IPs
            if src_ip == "N/A" or dst_ip == "N/A":
                continue
            
            # Extract HTTP fields
            http_full_url_path = packet.http.get('http.host', 'N/A') + packet.http.get('http.request.uri', 'N/A') if hasattr(packet, 'http') else "N/A"
            http_full_url_path = clean_http_data(http_full_url_path)
            
            # Initialize auth and form content
            http_auth_username = "N/A"
            http_auth_password = "N/A"
            http_form_content = "N/A"
            
            if hasattr(packet, 'http'):
                # Check for basic authentication
                auth_header = packet.http.get('http.authorization', 'N/A')
                if auth_header != 'N/A':
                    username, password = decode_basic_auth(auth_header)
                    if username and password:
                        http_auth_username = username
                        http_auth_password = password
                        logging.info(f"Found Basic Auth credentials for {src_ip} -> {dst_ip}: {username}:{password}")
                
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
                            http_form_content = clean_http_data(http_form_content)
                except (binascii.Error, UnicodeDecodeError, AttributeError):
                    http_form_content = "N/A"  # Return N/A if any conversion fails
            
            # Always add to extracted data if we have Basic Auth credentials
            if http_auth_username != "N/A" and http_auth_password != "N/A":
                extracted_data.append((src_ip, dst_ip, http_full_url_path, http_form_content, http_auth_username, http_auth_password))
            # Also add if we have form content
            elif http_form_content != "N/A":
                extracted_data.append((src_ip, dst_ip, http_full_url_path, http_form_content, http_auth_username, http_auth_password))
        
        except AttributeError:
            continue  # Skip packets that don't have the expected attributes
    
    capture.close()
    
    return extracted_data