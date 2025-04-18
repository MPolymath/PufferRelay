# Created by Massamba DIOUF
#
# This file is part of PufferRelay.
#
# PufferRelay is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PufferRelay is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PufferRelay. If not, see <http://www.gnu.org/licenses/>.
#
# Credits: Portions of this code were adapted from PCredz (https://github.com/lgandx/PCredz)
#         (c) Laurent Gaffie GNU General Public License v3.0.

from PufferRelay.core_imports import pyshark, re, base64, codecs, logging, struct, asyncio

# Global variables to store challenges
ntlm_challenge = None      # For non-HTTP packets (NTLMSSP2)
http_ntlm_challenge = None # For HTTP packets (HTTP NTLM2)

def is_anonymous(data):
    """Check if the NTLM authentication is anonymous."""
    try:
        lmhash_len = struct.unpack('<H', data[14:16])[0]
        logging.debug(f"LM Hash Length: {lmhash_len}")
        return lmhash_len > 1
    except Exception as e:
        logging.error(f"Error checking anonymous status: {str(e)}")
        return False

def parse_ntlm_hash(packet_data, challenge):
    """
    Extracts NTLM hashes from packet data using Pcredz logic.
    
    Args:
        packet_data (bytes): Raw packet data containing NTLM message
        challenge (bytes): The challenge value from NTLM type 2 message
        
    Returns:
        tuple: (formatted_hash, user_domain) or None if parsing fails
    """
    try:
        # Find the start of NTLMSSP message
        ntlmssp_start = packet_data.find(b'NTLMSSP\x00\x03')
        if ntlmssp_start == -1:
            logging.error("NTLMSSP3 signature not found")
            return None
            
        # Adjust packet_data to start at NTLMSSP message
        packet_data = packet_data[ntlmssp_start:]
        
        # Extract LM hash
        lmhash_len = struct.unpack('<H', packet_data[12:14])[0]
        lmhash_offset = struct.unpack('<H', packet_data[16:18])[0]
        lmhash = codecs.encode(packet_data[lmhash_offset:lmhash_offset+lmhash_len], "hex").upper()

        # Extract NT hash
        nthash_len = struct.unpack('<H', packet_data[20:22])[0]
        nthash_offset = struct.unpack('<H', packet_data[24:26])[0]
        
        # For NTLMv2, the NT hash includes the response
        if nthash_len > 24:  # NTLMv2
            # Extract the actual NT hash (first 16 bytes) and the response
            nthash = codecs.encode(packet_data[nthash_offset:nthash_offset+16], "hex").upper()
            response = codecs.encode(packet_data[nthash_offset+16:nthash_offset+nthash_len], "hex").upper()
        else:  # NTLMv1
            nthash = codecs.encode(packet_data[nthash_offset:nthash_offset+nthash_len], "hex").upper()

        # Extract domain and username
        domain_len = struct.unpack('<H', packet_data[28:30])[0]
        domain_offset = struct.unpack('<H', packet_data[32:34])[0]
        domain = packet_data[domain_offset:domain_offset+domain_len].replace(b"\x00", b"")

        user_len = struct.unpack('<H', packet_data[36:38])[0]
        user_offset = struct.unpack('<H', packet_data[40:42])[0]
        user = packet_data[user_offset:user_offset+user_len].replace(b"\x00", b"")

        # Format the hash based on NTLM version
        if nthash_len == 24:  # NTLMv1
            writehash = f"{user.decode('latin-1')}::{domain.decode('latin-1')}:{lmhash.decode('latin-1')}:{nthash.decode('latin-1')}:{challenge.decode('latin-1')}"
            return f"NTLMv1 complete hash is: {writehash}", f"{user.decode('latin-1')}::{domain.decode('latin-1')}"
        elif nthash_len > 24:  # NTLMv2
            # For NTLMv2, we use the challenge directly from the NTLMSSP2 message
            writehash = f"{user.decode('latin-1')}::{domain.decode('latin-1')}:{challenge.decode('latin-1')}:{nthash.decode('latin-1')}:{response.decode('latin-1')}"
            return f"NTLMv2 complete hash is: {writehash}", f"{user.decode('latin-1')}::{domain.decode('latin-1')}"
        
        logging.warning(f"Unexpected NT hash length: {nthash_len}")
        return None
    except Exception as e:
        logging.error(f"Error parsing NTLM hash: {str(e)}")
        return None

async def process_ntlm_async(pcap_file):
    """
    Processes a PCAP file to extract NTLM authentication data asynchronously.
    
    Args:
        pcap_file (str): Path to the PCAP file
        
    Returns:
        list: List of tuples containing (source_ip, destination_ip, username, ntlm_hash)
    """
    logging.info(f"Starting NTLM processing for file: {pcap_file}")
    extracted_data = []
    
    max_retries = 3
    retry_count = 0
    capture = None
    
    while retry_count < max_retries:
        try:
            # Open the capture file with a simpler filter
            capture = pyshark.FileCapture(
                pcap_file,
                display_filter="tcp",
                use_json=True,  # Use JSON output for better stability
                include_raw=True,  # Include raw packet data
                debug=True  # Enable debug mode
            )
            
            # Enable debug mode for TShark
            capture.set_debug()
            
            # Dictionary to store challenges by source-destination IP pair
            challenges = {}
            processed_hashes = set()  # Track processed hashes to avoid duplicates
            packet_count = 0  # Track packet number for debugging
            
            for packet in capture:
                packet_count += 1
                try:
                    # Extract source and destination IPs
                    src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
                    dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
                    
                    if src_ip == "N/A" or dst_ip == "N/A":
                        continue
                    
                    # Process NTLMSSP messages
                    if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
                        raw_str = packet.tcp.payload.replace(":", "")
                        
                        if len(raw_str) % 2 == 0:  # Ensure even length
                            raw_data = bytes.fromhex(raw_str)
                            
                            # Check for NTLMSSP2 (challenge)
                            if re.search(b'NTLMSSP\x00\x02\x00\x00\x00', raw_data, re.DOTALL):
                                # Extract the challenge from the NTLMSSP2 message
                                # Find the NTLMSSP signature first
                                ntlmssp_start = raw_data.find(b'NTLMSSP\x00\x02')
                                if ntlmssp_start == -1:
                                    logging.error("NTLMSSP2 signature not found")
                                    continue
                                
                                # The challenge is at offset 24 from the start of NTLMSSP
                                challenge_offset = ntlmssp_start + 24
                                if challenge_offset + 8 > len(raw_data):
                                    logging.error(f"Challenge offset {challenge_offset} out of bounds for data length {len(raw_data)}")
                                    continue
                                    
                                challenge = codecs.encode(raw_data[challenge_offset:challenge_offset+8], 'hex')
                                
                                # Store challenge for this IP pair
                                ip_pair = (src_ip, dst_ip)
                                challenges[ip_pair] = challenge
                            
                            # Check for NTLMSSP3 (authentication)
                            elif re.search(b'NTLMSSP\x00\x03\x00\x00\x00', raw_data, re.DOTALL):
                                # Look for challenge in both directions
                                ip_pair = (src_ip, dst_ip)
                                reverse_pair = (dst_ip, src_ip)
                                
                                challenge = None
                                if ip_pair in challenges:
                                    challenge = challenges[ip_pair]
                                elif reverse_pair in challenges:
                                    challenge = challenges[reverse_pair]
                                else:
                                    logging.warning(f"No challenge found for NTLMSSP3 message. IP pair: {ip_pair}, Reverse pair: {reverse_pair}")
                                
                                if challenge:
                                    result = parse_ntlm_hash(raw_data, challenge)
                                    if result:
                                        # Create a unique identifier for this hash using username, challenge, and NT hash
                                        hash_id = f"{result[1]}:{challenge.decode('latin-1')}:{result[0].split(':')[3]}"
                                        
                                        # Only process if we haven't seen this hash before
                                        if hash_id not in processed_hashes:
                                            processed_hashes.add(hash_id)
                                            extracted_data.append((src_ip, dst_ip, result[1], result[0]))
                    
                    # Process HTTP NTLM messages
                    if hasattr(packet, 'http'):
                        # Check for NTLM2 challenge
                        if hasattr(packet.http, 'www_authenticate'):
                            www_auth = packet.http.www_authenticate
                            
                            if "NTLM " in www_auth:
                                b64_data = www_auth.split("NTLM ")[1].strip()
                                
                                try:
                                    decoded = base64.b64decode(b64_data)
                                    
                                    if re.search(b'NTLMSSP\x00\x02\x00\x00\x00', decoded):
                                        # Extract the challenge from the HTTP NTLM2 message
                                        # The challenge is at offset 24 and is 8 bytes long
                                        challenge = codecs.encode(decoded[24:32], 'hex')
                                        
                                        # Store challenge for this IP pair
                                        ip_pair = (src_ip, dst_ip)
                                        challenges[ip_pair] = challenge
                                except Exception as e:
                                    logging.error(f"Error decoding HTTP NTLM2: {str(e)}")
                        
                        # Check for NTLM3 authentication
                        if hasattr(packet.http, 'authorization'):
                            auth_header = packet.http.authorization
                            
                            if "NTLM " in auth_header:
                                b64_data = auth_header.split("NTLM ")[1].strip()
                                
                                try:
                                    decoded = base64.b64decode(b64_data)
                                    
                                    if re.search(b'NTLMSSP\x00\x03\x00\x00\x00', decoded):
                                        # Look for challenge in both directions
                                        ip_pair = (src_ip, dst_ip)
                                        reverse_pair = (dst_ip, src_ip)
                                        
                                        challenge = None
                                        if ip_pair in challenges:
                                            challenge = challenges[ip_pair]
                                        elif reverse_pair in challenges:
                                            challenge = challenges[reverse_pair]
                                        else:
                                            logging.warning(f"No challenge found for HTTP NTLM3 message. IP pair: {ip_pair}, Reverse pair: {reverse_pair}")
                                        
                                        if challenge:
                                            result = parse_ntlm_hash(decoded, challenge)
                                            if result:
                                                # Create a unique identifier for this hash using username, challenge, and NT hash
                                                hash_id = f"{result[1]}:{challenge.decode('latin-1')}:{result[0].split(':')[3]}"
                                                
                                                # Only process if we haven't seen this hash before
                                                if hash_id not in processed_hashes:
                                                    processed_hashes.add(hash_id)
                                                    extracted_data.append((src_ip, dst_ip, result[1], result[0]))
                                except Exception as e:
                                    logging.error(f"Error decoding HTTP NTLM3: {str(e)}")
                        
                except Exception as e:
                    logging.error(f"Error processing packet #{packet_count}: {str(e)}")
                    continue
            
            # If we get here, the capture was successful
            logging.info(f"Successfully processed {packet_count} packets")
            return extracted_data
                
        except Exception as e:
            retry_count += 1
            logging.error(f"Error processing NTLM packets (attempt {retry_count}/{max_retries}): {str(e)}")
            if retry_count < max_retries:
                logging.info("Retrying capture...")
                continue
            else:
                logging.error("Max retries reached. Giving up.")
                raise
        finally:
            # Properly close the capture in the finally block
            if capture is not None:
                try:
                    await capture.close_async()
                except Exception as e:
                    logging.error(f"Error closing capture: {str(e)}")
    
    return extracted_data

def process_ntlm(pcap_file):
    """
    Processes a PCAP file to extract NTLM authentication data.
    
    Args:
        pcap_file (str): Path to the PCAP file
        
    Returns:
        list: List of tuples containing (source_ip, destination_ip, username, ntlm_hash)
    """
    logging.info(f"Starting NTLM processing for file: {pcap_file}")
    extracted_data = []
    
    max_retries = 3
    retry_count = 0
    capture = None
    
    while retry_count < max_retries:
        try:
            # Open the capture file with a simpler filter
            capture = pyshark.FileCapture(
                pcap_file,
                display_filter="tcp",
                use_json=True,  # Use JSON output for better stability
                include_raw=True,  # Include raw packet data
                debug=True  # Enable debug mode
            )
            
            # Enable debug mode for TShark
            capture.set_debug()
            
            # Dictionary to store challenges by source-destination IP pair
            challenges = {}
            processed_hashes = set()  # Track processed hashes to avoid duplicates
            packet_count = 0  # Track packet number for debugging
            
            for packet in capture:
                packet_count += 1
                try:
                    # Extract source and destination IPs
                    src_ip = packet.ip.src if hasattr(packet, 'ip') else "N/A"
                    dst_ip = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
                    
                    if src_ip == "N/A" or dst_ip == "N/A":
                        continue
                    
                    # Process NTLMSSP messages
                    if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
                        raw_str = packet.tcp.payload.replace(":", "")
                        
                        if len(raw_str) % 2 == 0:  # Ensure even length
                            raw_data = bytes.fromhex(raw_str)
                            
                            # Check for NTLMSSP2 (challenge)
                            if re.search(b'NTLMSSP\x00\x02\x00\x00\x00', raw_data, re.DOTALL):
                                # Extract the challenge from the NTLMSSP2 message
                                # Find the NTLMSSP signature first
                                ntlmssp_start = raw_data.find(b'NTLMSSP\x00\x02')
                                if ntlmssp_start == -1:
                                    logging.error("NTLMSSP2 signature not found")
                                    continue
                                
                                # The challenge is at offset 24 from the start of NTLMSSP
                                challenge_offset = ntlmssp_start + 24
                                if challenge_offset + 8 > len(raw_data):
                                    logging.error(f"Challenge offset {challenge_offset} out of bounds for data length {len(raw_data)}")
                                    continue
                                    
                                challenge = codecs.encode(raw_data[challenge_offset:challenge_offset+8], 'hex')
                                
                                # Store challenge for this IP pair
                                ip_pair = (src_ip, dst_ip)
                                challenges[ip_pair] = challenge
                            
                            # Check for NTLMSSP3 (authentication)
                            elif re.search(b'NTLMSSP\x00\x03\x00\x00\x00', raw_data, re.DOTALL):
                                # Look for challenge in both directions
                                ip_pair = (src_ip, dst_ip)
                                reverse_pair = (dst_ip, src_ip)
                                
                                challenge = None
                                if ip_pair in challenges:
                                    challenge = challenges[ip_pair]
                                elif reverse_pair in challenges:
                                    challenge = challenges[reverse_pair]
                                else:
                                    logging.warning(f"No challenge found for NTLMSSP3 message. IP pair: {ip_pair}, Reverse pair: {reverse_pair}")
                                
                                if challenge:
                                    result = parse_ntlm_hash(raw_data, challenge)
                                    if result:
                                        # Create a unique identifier for this hash using username, challenge, and NT hash
                                        hash_id = f"{result[1]}:{challenge.decode('latin-1')}:{result[0].split(':')[3]}"
                                        
                                        # Only process if we haven't seen this hash before
                                        if hash_id not in processed_hashes:
                                            processed_hashes.add(hash_id)
                                            extracted_data.append((src_ip, dst_ip, result[1], result[0]))
                    
                    # Process HTTP NTLM messages
                    if hasattr(packet, 'http'):
                        # Check for NTLM2 challenge
                        if hasattr(packet.http, 'www_authenticate'):
                            www_auth = packet.http.www_authenticate
                            
                            if "NTLM " in www_auth:
                                b64_data = www_auth.split("NTLM ")[1].strip()
                                
                                try:
                                    decoded = base64.b64decode(b64_data)
                                    
                                    if re.search(b'NTLMSSP\x00\x02\x00\x00\x00', decoded):
                                        # Extract the challenge from the HTTP NTLM2 message
                                        # The challenge is at offset 24 and is 8 bytes long
                                        challenge = codecs.encode(decoded[24:32], 'hex')
                                        
                                        # Store challenge for this IP pair
                                        ip_pair = (src_ip, dst_ip)
                                        challenges[ip_pair] = challenge
                                except Exception as e:
                                    logging.error(f"Error decoding HTTP NTLM2: {str(e)}")
                        
                        # Check for NTLM3 authentication
                        if hasattr(packet.http, 'authorization'):
                            auth_header = packet.http.authorization
                            
                            if "NTLM " in auth_header:
                                b64_data = auth_header.split("NTLM ")[1].strip()
                                
                                try:
                                    decoded = base64.b64decode(b64_data)
                                    
                                    if re.search(b'NTLMSSP\x00\x03\x00\x00\x00', decoded):
                                        # Look for challenge in both directions
                                        ip_pair = (src_ip, dst_ip)
                                        reverse_pair = (dst_ip, src_ip)
                                        
                                        challenge = None
                                        if ip_pair in challenges:
                                            challenge = challenges[ip_pair]
                                        elif reverse_pair in challenges:
                                            challenge = challenges[reverse_pair]
                                        else:
                                            logging.warning(f"No challenge found for HTTP NTLM3 message. IP pair: {ip_pair}, Reverse pair: {reverse_pair}")
                                        
                                        if challenge:
                                            result = parse_ntlm_hash(decoded, challenge)
                                            if result:
                                                # Create a unique identifier for this hash using username, challenge, and NT hash
                                                hash_id = f"{result[1]}:{challenge.decode('latin-1')}:{result[0].split(':')[3]}"
                                                
                                                # Only process if we haven't seen this hash before
                                                if hash_id not in processed_hashes:
                                                    processed_hashes.add(hash_id)
                                                    extracted_data.append((src_ip, dst_ip, result[1], result[0]))
                                except Exception as e:
                                    logging.error(f"Error decoding HTTP NTLM3: {str(e)}")
                        
                except Exception as e:
                    logging.error(f"Error processing packet #{packet_count}: {str(e)}")
                    continue
            
            # If we get here, the capture was successful
            logging.info(f"Successfully processed {packet_count} packets")
            return extracted_data
                
        except Exception as e:
            retry_count += 1
            logging.error(f"Error processing NTLM packets (attempt {retry_count}/{max_retries}): {str(e)}")
            if retry_count < max_retries:
                logging.info("Retrying capture...")
                continue
            else:
                logging.error("Max retries reached. Giving up.")
                raise
        finally:
            # Properly close the capture in the finally block
            if capture is not None:
                try:
                    # Get the process before closing
                    process = getattr(capture, '_tshark_process', None)
                    if process:
                        # Kill the process directly
                        process.kill()
                        process.wait()
                    # Then close the capture
                    capture.close()
                except Exception as e:
                    logging.error(f"Error closing capture: {str(e)}")
    
    return extracted_data