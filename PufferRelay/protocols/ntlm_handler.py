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
        logging.debug(f"Raw packet data length: {len(packet_data)}")
        logging.debug(f"Raw packet data: {packet_data.hex()}")
        
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
        logging.debug(f"LM Hash - Length: {lmhash_len}, Offset: {lmhash_offset}")
        lmhash = codecs.encode(packet_data[lmhash_offset:lmhash_offset+lmhash_len], "hex").upper()
        logging.debug(f"LM Hash: {lmhash.decode('latin-1')}")

        # Extract NT hash
        nthash_len = struct.unpack('<H', packet_data[20:22])[0]
        nthash_offset = struct.unpack('<H', packet_data[24:26])[0]
        logging.debug(f"NT Hash - Length: {nthash_len}, Offset: {nthash_offset}")
        
        # For NTLMv2, the NT hash includes the response
        if nthash_len > 24:  # NTLMv2
            # Extract the actual NT hash (first 16 bytes) and the response
            nthash = codecs.encode(packet_data[nthash_offset:nthash_offset+16], "hex").upper()
            response = codecs.encode(packet_data[nthash_offset+16:nthash_offset+nthash_len], "hex").upper()
            logging.debug(f"NT Hash (NTLMv2): {nthash.decode('latin-1')}")
            logging.debug(f"Response: {response.decode('latin-1')}")
        else:  # NTLMv1
            nthash = codecs.encode(packet_data[nthash_offset:nthash_offset+nthash_len], "hex").upper()
            logging.debug(f"NT Hash (NTLMv1): {nthash.decode('latin-1')}")

        # Extract domain and username
        domain_len = struct.unpack('<H', packet_data[28:30])[0]
        domain_offset = struct.unpack('<H', packet_data[32:34])[0]
        logging.debug(f"Domain - Length: {domain_len}, Offset: {domain_offset}")
        domain = packet_data[domain_offset:domain_offset+domain_len].replace(b"\x00", b"")
        logging.debug(f"Domain: {domain.decode('latin-1')}")

        user_len = struct.unpack('<H', packet_data[36:38])[0]
        user_offset = struct.unpack('<H', packet_data[40:42])[0]
        logging.debug(f"User - Length: {user_len}, Offset: {user_offset}")
        user = packet_data[user_offset:user_offset+user_len].replace(b"\x00", b"")
        logging.debug(f"User: {user.decode('latin-1')}")

        # Format the hash based on NTLM version
        if nthash_len == 24:  # NTLMv1
            writehash = f"{user.decode('latin-1')}::{domain.decode('latin-1')}:{lmhash.decode('latin-1')}:{nthash.decode('latin-1')}:{challenge.decode('latin-1')}"
            logging.debug(f"NTLMv1 Hash: {writehash}")
            return f"NTLMv1 complete hash is: {writehash}", f"{user.decode('latin-1')}::{domain.decode('latin-1')}"
        elif nthash_len > 24:  # NTLMv2
            # For NTLMv2, we use the challenge directly from the NTLMSSP2 message
            writehash = f"{user.decode('latin-1')}::{domain.decode('latin-1')}:{challenge.decode('latin-1')}:{nthash.decode('latin-1')}:{response.decode('latin-1')}"
            logging.debug(f"NTLMv2 Hash: {writehash}")
            return f"NTLMv2 complete hash is: {writehash}", f"{user.decode('latin-1')}::{domain.decode('latin-1')}"
        
        logging.warning(f"Unexpected NT hash length: {nthash_len}")
        return None
    except Exception as e:
        logging.error(f"Error parsing NTLM hash: {str(e)}")
        return None

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
    
    try:
        # Open the capture file with a simpler filter
        with pyshark.FileCapture(pcap_file, display_filter="tcp") as capture:
            capture.set_debug()  # Enable debug mode for TShark
            
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
                    
                    logging.debug(f"\n{'='*80}")
                    logging.debug(f"Processing Packet #{packet_count}")
                    logging.debug(f"Source IP: {src_ip}")
                    logging.debug(f"Destination IP: {dst_ip}")
                    logging.debug(f"Packet length: {len(packet)}")
                    
                    if src_ip == "N/A" or dst_ip == "N/A":
                        logging.debug("Skipping packet - missing IP information")
                        continue
                    
                    # Process NTLMSSP messages
                    if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
                        raw_str = packet.tcp.payload.replace(":", "")
                        
                        if len(raw_str) % 2 == 0:  # Ensure even length
                            raw_data = bytes.fromhex(raw_str)
                            logging.debug(f"Raw TCP payload length: {len(raw_data)}")
                            logging.debug(f"Raw TCP payload (hex): {raw_data.hex()}")
                            logging.debug(f"Raw TCP payload (hex with spaces): {' '.join([raw_data[i:i+2].hex() for i in range(0, len(raw_data), 2)])}")
                            
                            # Check for NTLMSSP2 (challenge)
                            if re.search(b'NTLMSSP\x00\x02\x00\x00\x00', raw_data, re.DOTALL):
                                logging.debug(f"\n{'='*80}")
                                logging.debug(f"Packet #{packet_count} - NTLMSSP2 Message")
                                logging.debug(f"Source IP: {src_ip}")
                                logging.debug(f"Destination IP: {dst_ip}")
                                logging.debug(f"Full NTLMSSP2 message (hex): {raw_data.hex()}")
                                logging.debug(f"Full NTLMSSP2 message (hex with spaces): {' '.join([raw_data[i:i+2].hex() for i in range(0, len(raw_data), 2)])}")
                                
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
                                logging.debug(f"NTLMSSP2 detected. Challenge: {challenge.decode('latin-1')}")
                                logging.debug(f"Challenge bytes: {raw_data[challenge_offset:challenge_offset+8].hex()}")
                                logging.debug(f"Challenge offset: {challenge_offset}")
                                logging.debug(f"Challenge length: 8")
                                
                                # Store challenge for this IP pair
                                ip_pair = (src_ip, dst_ip)
                                challenges[ip_pair] = challenge
                                logging.debug(f"Stored challenge for {ip_pair}")
                                logging.debug(f"Current challenges in memory: {[(k, v.decode('latin-1')) for k, v in challenges.items()]}")
                            
                            # Check for NTLMSSP3 (authentication)
                            elif re.search(b'NTLMSSP\x00\x03\x00\x00\x00', raw_data, re.DOTALL):
                                logging.debug(f"\n{'='*80}")
                                logging.debug(f"Packet #{packet_count} - NTLMSSP3 Message")
                                logging.debug(f"Source IP: {src_ip}")
                                logging.debug(f"Destination IP: {dst_ip}")
                                logging.debug(f"Full NTLMSSP3 message (hex): {raw_data.hex()}")
                                logging.debug(f"Full NTLMSSP3 message (hex with spaces): {' '.join([raw_data[i:i+2].hex() for i in range(0, len(raw_data), 2)])}")
                                
                                # Look for challenge in both directions
                                ip_pair = (src_ip, dst_ip)
                                reverse_pair = (dst_ip, src_ip)
                                
                                logging.debug(f"Looking for challenge for IP pair: {ip_pair}")
                                logging.debug(f"Looking for challenge for reverse pair: {reverse_pair}")
                                
                                challenge = None
                                if ip_pair in challenges:
                                    challenge = challenges[ip_pair]
                                    logging.debug(f"Found challenge for {ip_pair}: {challenge.decode('latin-1')}")
                                elif reverse_pair in challenges:
                                    challenge = challenges[reverse_pair]
                                    logging.debug(f"Found challenge for {reverse_pair}: {challenge.decode('latin-1')}")
                                else:
                                    logging.warning(f"No challenge found for NTLMSSP3 message. IP pair: {ip_pair}, Reverse pair: {reverse_pair}")
                                    logging.debug(f"Available challenges: {[(k, v.decode('latin-1')) for k, v in challenges.items()]}")
                                
                                if challenge:
                                    result = parse_ntlm_hash(raw_data, challenge)
                                    if result:
                                        # Create a unique identifier for this hash using username, challenge, and NT hash
                                        hash_id = f"{result[1]}:{challenge.decode('latin-1')}:{result[0].split(':')[3]}"
                                        logging.debug(f"Generated hash ID: {hash_id}")
                                        
                                        # Only process if we haven't seen this hash before
                                        if hash_id not in processed_hashes:
                                            processed_hashes.add(hash_id)
                                            logging.info(f"\nNTLMSSP Authentication Found:")
                                            logging.info(f"Source IP: {src_ip}")
                                            logging.info(f"Destination IP: {dst_ip}")
                                            logging.info(f"Challenge: {challenge.decode('latin-1')}")
                                            logging.info(f"Hash: {result[0]}")
                                            logging.info(f"User: {result[1]}")
                                            logging.info("=" * 50)
                                            extracted_data.append((src_ip, dst_ip, result[1], result[0]))
                                        else:
                                            logging.debug(f"Skipping duplicate hash for {result[1]} with challenge {challenge.decode('latin-1')}")
                                            logging.debug(f"Hash ID already processed: {hash_id}")
                                    else:
                                        logging.warning("Failed to parse NTLM hash from NTLMSSP3 message")
                                        logging.debug(f"Raw data that failed parsing: {raw_data.hex()}")
                                else:
                                    logging.warning("NTLMSSP3 message found but no challenge available")
                                    logging.debug(f"Raw NTLMSSP3 message: {raw_data.hex()}")
                    
                    # Process HTTP NTLM messages
                    if hasattr(packet, 'http'):
                        logging.debug(f"\n{'='*80}")
                        logging.debug(f"Packet #{packet_count} - HTTP Layer")
                        logging.debug(f"Source IP: {src_ip}")
                        logging.debug(f"Destination IP: {dst_ip}")
                        
                        # Check for NTLM2 challenge
                        if hasattr(packet.http, 'www_authenticate'):
                            www_auth = packet.http.www_authenticate
                            logging.debug(f"WWW-Authenticate header: {www_auth}")
                            
                            if "NTLM " in www_auth:
                                b64_data = www_auth.split("NTLM ")[1].strip()
                                logging.debug(f"Base64 NTLM data: {b64_data}")
                                
                                try:
                                    decoded = base64.b64decode(b64_data)
                                    logging.debug(f"Decoded NTLM data length: {len(decoded)}")
                                    logging.debug(f"Decoded NTLM data (hex): {decoded.hex()}")
                                    
                                    if re.search(b'NTLMSSP\x00\x02\x00\x00\x00', decoded):
                                        logging.debug(f"\n{'='*80}")
                                        logging.debug(f"Packet #{packet_count} - HTTP NTLM2 Message")
                                        logging.debug(f"Source IP: {src_ip}")
                                        logging.debug(f"Destination IP: {dst_ip}")
                                        logging.debug(f"Full HTTP NTLM2 message (hex): {decoded.hex()}")
                                        logging.debug(f"Full HTTP NTLM2 message (hex with spaces): {' '.join([decoded[i:i+2].hex() for i in range(0, len(decoded), 2)])}")
                                        
                                        # Extract the challenge from the HTTP NTLM2 message
                                        # The challenge is at offset 24 and is 8 bytes long
                                        challenge = codecs.encode(decoded[24:32], 'hex')
                                        logging.debug(f"HTTP NTLM2 detected. Challenge: {challenge.decode('latin-1')}")
                                        logging.debug(f"Challenge bytes: {decoded[24:32].hex()}")
                                        logging.debug(f"Challenge offset: 24")
                                        logging.debug(f"Challenge length: 8")
                                        
                                        # Store challenge for this IP pair
                                        ip_pair = (src_ip, dst_ip)
                                        challenges[ip_pair] = challenge
                                        logging.debug(f"Stored HTTP NTLM challenge for {ip_pair}")
                                        logging.debug(f"Current challenges in memory: {[(k, v.decode('latin-1')) for k, v in challenges.items()]}")
                                except Exception as e:
                                    logging.error(f"Error decoding HTTP NTLM2: {str(e)}")
                                    logging.debug(f"Raw WWW-Authenticate header: {www_auth}")
                                    logging.debug(f"Base64 data that failed: {b64_data}")
                        
                        # Check for NTLM3 authentication
                        if hasattr(packet.http, 'authorization'):
                            auth_header = packet.http.authorization
                            logging.debug(f"Authorization header: {auth_header}")
                            
                            if "NTLM " in auth_header:
                                b64_data = auth_header.split("NTLM ")[1].strip()
                                logging.debug(f"Base64 NTLM data: {b64_data}")
                                
                                try:
                                    decoded = base64.b64decode(b64_data)
                                    logging.debug(f"Decoded NTLM data length: {len(decoded)}")
                                    logging.debug(f"Decoded NTLM data (hex): {decoded.hex()}")
                                    
                                    if re.search(b'NTLMSSP\x00\x03\x00\x00\x00', decoded):
                                        logging.debug(f"\n{'='*80}")
                                        logging.debug(f"Packet #{packet_count} - HTTP NTLM3 Message")
                                        logging.debug(f"Source IP: {src_ip}")
                                        logging.debug(f"Destination IP: {dst_ip}")
                                        logging.debug(f"Full HTTP NTLM3 message (hex): {decoded.hex()}")
                                        logging.debug(f"Full HTTP NTLM3 message (hex with spaces): {' '.join([decoded[i:i+2].hex() for i in range(0, len(decoded), 2)])}")
                                        
                                        # Look for challenge in both directions
                                        ip_pair = (src_ip, dst_ip)
                                        reverse_pair = (dst_ip, src_ip)
                                        
                                        logging.debug(f"Looking for challenge for IP pair: {ip_pair}")
                                        logging.debug(f"Looking for challenge for reverse pair: {reverse_pair}")
                                        
                                        challenge = None
                                        if ip_pair in challenges:
                                            challenge = challenges[ip_pair]
                                            logging.debug(f"Found HTTP challenge for {ip_pair}: {challenge.decode('latin-1')}")
                                        elif reverse_pair in challenges:
                                            challenge = challenges[reverse_pair]
                                            logging.debug(f"Found HTTP challenge for {reverse_pair}: {challenge.decode('latin-1')}")
                                        else:
                                            logging.warning(f"No challenge found for HTTP NTLM3 message. IP pair: {ip_pair}, Reverse pair: {reverse_pair}")
                                            logging.debug(f"Available challenges: {[(k, v.decode('latin-1')) for k, v in challenges.items()]}")
                                        
                                        if challenge:
                                            result = parse_ntlm_hash(decoded, challenge)
                                            if result:
                                                # Create a unique identifier for this hash using username, challenge, and NT hash
                                                hash_id = f"{result[1]}:{challenge.decode('latin-1')}:{result[0].split(':')[3]}"
                                                logging.debug(f"Generated hash ID: {hash_id}")
                                                
                                                # Only process if we haven't seen this hash before
                                                if hash_id not in processed_hashes:
                                                    processed_hashes.add(hash_id)
                                                    logging.info(f"\nHTTP NTLM Authentication Found:")
                                                    logging.info(f"Source IP: {src_ip}")
                                                    logging.info(f"Destination IP: {dst_ip}")
                                                    logging.info(f"Challenge: {challenge.decode('latin-1')}")
                                                    logging.info(f"Hash: {result[0]}")
                                                    logging.info(f"User: {result[1]}")
                                                    logging.info("=" * 50)
                                                    extracted_data.append((src_ip, dst_ip, result[1], result[0]))
                                                else:
                                                    logging.debug(f"Skipping duplicate hash for {result[1]} with challenge {challenge.decode('latin-1')}")
                                                    logging.debug(f"Hash ID already processed: {hash_id}")
                                            else:
                                                logging.warning("Failed to parse NTLM hash from HTTP NTLM3 message")
                                                logging.debug(f"Raw data that failed parsing: {decoded.hex()}")
                                        else:
                                            logging.warning("HTTP NTLM3 message found but no challenge available")
                                            logging.debug(f"Raw NTLMSSP3 message: {decoded.hex()}")
                                except Exception as e:
                                    logging.error(f"Error decoding HTTP NTLM3: {str(e)}")
                                    logging.debug(f"Raw Authorization header: {auth_header}")
                                    logging.debug(f"Base64 data that failed: {b64_data}")
                        
                except Exception as e:
                    logging.error(f"Error processing packet #{packet_count}: {str(e)}")
                    logging.debug(f"Packet that caused error: {packet}")
                    continue
                    
    except Exception as e:
        logging.error(f"Error processing NTLM packets: {str(e)}")
        logging.debug(f"Error occurred while processing file: {pcap_file}")
    
    logging.info(f"Found {len(extracted_data)} NTLM entries")
    logging.debug(f"Final list of extracted data: {extracted_data}")
    return extracted_data