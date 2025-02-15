from PufferRelay.protocols.ldap_handler import process_ldap
from PufferRelay.protocols.http_handler import process_http
from PufferRelay.protocols.ftp_handler import process_ftp
from PufferRelay.core_imports import logging

def parse_pcap(pcap_file):
    """
    Parses a PCAP file and extracts data for LDAP, HTTP, and FTP.

    Args:
        pcap_file (str): Path to the .pcap file.

    Returns:
        dict: Extracted data categorized by protocol.
    """
    logging.info(f"Parsing PCAP file: {pcap_file}")

    ldap_data = process_ldap(pcap_file)
    http_data = process_http(pcap_file)
    ftp_data = process_ftp(pcap_file)

    return {
        "ldap": ldap_data,
        "http": http_data,
        "ftp": ftp_data
    }