import re
import logging
from PufferRelay.core_imports import pyshark
from PufferRelay.database.db_queries import update_quick_win

def analyze_quick_wins(pcap_file, conn):
    """
    Analyze a PCAP file for quick wins (unencrypted protocols, deprecated versions, etc.)
    
    Args:
        pcap_file (str): Path to the PCAP file
        conn: Database connection
    """
    # Define regex patterns for each protocol
    protocol_patterns = {
        # Unencrypted protocols
        'LDAP': r'ldap|ldap3|ldaps|ldap-secure|ldap-ssl|ldaps-ssl',
        'HTTP': r'(?:^|\s)(?:http/1\.\d|http/2|http1\.\d|http2)(?:\s|$)|(?:^|\s)http(?:\s|$)',
        'FTP': r'ftp|ftps|ftp-secure|ftp-ssl|ftps-ssl',
        'TELNET': r'telnet|telnet-ssl|telnet-secure',
        'SMTP': r'smtp|smtps|smtp-secure|smtp-ssl|smtps-ssl',
        'IMAP': r'imap|imaps|imap-secure|imap-ssl|imaps-ssl',
        'POP3': r'pop3|pop|pop3s|pop3-secure|pop3s-secure|pop3-ssl|pop3s-ssl',
        'SYSLOG': r'syslog|rsyslog|syslog-ng',
        'TFTP': r'tftp|trivial file transfer protocol',
        
        # Deprecated protocols
        'SNMPv1': r'version-1 \(0\)|version: version-1|version-1|version 1',
        'SNMPv2': r'version-2 \(1\)|version: version-2|version-2|version 2',
        'SMBv1': r'smbv1|smb v1|smb version 1',
        'TLS1.0': r'tlsv1\.0|tls v1\.0|tls version 1\.0',
        'SSLv2': r'sslv2|ssl v2|ssl version 2',
        'SSLv3': r'sslv3|ssl v3|ssl version 3',
        
        # Multicast protocols
        'LLMNR': r'llmnr|link-local multicast name resolution',
        'NETBIOS': r'netbios|nbns|nbss|nbdgm|nbname|nbdatagram',
        'MDNS': r'mdns|multicast dns|bonjour',
        
        # Security issues
        'LDAP_SIGNING_MISSING': r'ldap signing|ldap channel binding',
        'LDAP_SIGNING_ENFORCED': r'ldap signing required|ldap channel binding required',
        'SMB_SIGNING_MISSING': r'smb signing|smb message signing'
    }
    
    # Define credential patterns for each protocol that can have credentials
    credential_patterns = {
        'LDAP': r'(?i)(?:user|username|password|pass|pwd|binddn|bindpw)',
        'HTTP': r'(?i)(?:user|username|password|pass|pwd|login|auth)',
        'FTP': r'(?i)(?:user|username|password|pass|pwd|login)',
        'TELNET': r'(?i)(?:user|username|password|pass|pwd|login)',
        'SMTP': r'(?i)(?:user|username|password|pass|pwd|login|auth)',
        'IMAP': r'(?i)(?:user|username|password|pass|pwd|login|auth)',
        'POP3': r'(?i)(?:user|username|password|pass|pwd|login|auth)',
        'SYSLOG': r'(?i)(?:user|username|password|pass|pwd|login|auth)',
        'TFTP': r'(?i)(?:user|username|password|pass|pwd|login)'
    }
    
    try:
        # Get current state of quick wins
        cursor = conn.cursor()
        cursor.execute("SELECT protocol, found, details, credentials_found, credential_protocols FROM quick_wins")
        current_state = {row[0]: row[1:] for row in cursor.fetchall()}
        
        # Open the PCAP file
        capture = pyshark.FileCapture(pcap_file)
        
        # Track found protocols and credentials
        found_protocols = set()
        credential_protocols = set()
        
        # Process each packet
        for packet in capture:
            try:
                # Get packet info as string
                packet_info = str(packet).lower()
                
                # Check each protocol pattern
                for protocol, pattern in protocol_patterns.items():
                    if re.search(pattern, packet_info, re.IGNORECASE):
                        # For HTTP, do additional verification
                        if protocol == 'HTTP':
                            # Check if this is actually an HTTP packet
                            if not any(method in packet_info for method in ['get ', 'post ', 'put ', 'delete ', 'head ', 'options ', 'trace ', 'connect ']):
                                continue
                        
                        # For SNMP, do additional verification
                        if protocol.startswith('SNMP'):
                            # Check if this is actually an SNMP packet
                            if not any(snmp in packet_info for snmp in ['snmp', 'community', 'oid', 'mib']):
                                continue
                            
                            # Log the packet info for debugging
                            #logging.debug(f"SNMP packet info: {packet_info[:500]}")
                        
                        found_protocols.add(protocol)
                        #logging.debug(f"Found {protocol} in packet: {packet_info[:200]}...")
                        
                        # Check for credentials only in protocols that can have them
                        if protocol in credential_patterns:
                            if re.search(credential_patterns[protocol], packet_info, re.IGNORECASE):
                                credential_protocols.add(protocol)
                                logging.debug(f"Found credentials in {protocol} packet")
                
            except Exception as e:
                logging.debug(f"Error processing packet: {str(e)}")
                continue
        
        # Update quick wins in database
        for protocol in protocol_patterns.keys():
            # Get current state for this protocol
            current_found, current_details, current_credentials_found, current_credential_protocols = current_state.get(protocol, (False, '', False, ''))
            
            # Update found status (preserve previous findings)
            found = current_found or (protocol in found_protocols)
            
            # Update credentials status (only for protocols that can have credentials)
            credentials_found = current_credentials_found
            if protocol in credential_patterns:
                credentials_found = current_credentials_found or (protocol in credential_protocols)
            
            # Merge credential protocols
            current_protocols = set(current_credential_protocols.split(',')) if current_credential_protocols else set()
            new_protocols = current_protocols.union({protocol} if protocol in credential_protocols else set())
            credential_protocols_str = ','.join(sorted(new_protocols)) if new_protocols else ''
            
            # Add details about the finding
            details = current_details
            if protocol in found_protocols:
                if protocol in credential_protocols:
                    details = "Credentials found in traffic" if not details else details
                else:
                    details = "Protocol found in traffic" if not details else details
            
            # Update the quick win entry
            update_quick_win(
                conn,
                protocol,
                found=found,
                details=details,
                credentials_found=credentials_found,
                credential_protocols=credential_protocols_str.split(',') if credential_protocols_str else None
            )
            
            logging.info(f"Updated quick win for {protocol}: found={found}, credentials={credentials_found}")
    
    except Exception as e:
        logging.error(f"Error analyzing quick wins: {str(e)}")
        raise
    finally:
        if 'capture' in locals():
            capture.close() 