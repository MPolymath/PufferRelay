from PufferRelay.protocols import process_ldap, process_http, process_ftp, process_telnet, process_smtp, process_ips, process_ntlm
from PufferRelay.core_imports import logging

def parse_pcap(pcap_file):
    """
    Parses a PCAP file and extracts data for LDAP, HTTP, FTP, TELNET, SMTP, NTLM, and IPs.

    Args:
        pcap_file (str): Path to the .pcap file.

    Returns:
        dict: Extracted data categorized by protocol.
    """
    logging.info(f"Parsing PCAP file: {pcap_file}")

    ldap_data = process_ldap(pcap_file)
    http_data = process_http(pcap_file)
    ftp_data = process_ftp(pcap_file)
    telnet_data = process_telnet(pcap_file)
    smtp_data = process_smtp(pcap_file)
    ntlm_data = process_ntlm(pcap_file)
    ip_data = process_ips(pcap_file)

    return {
        "ldap": ldap_data,
        "http": http_data,
        "ftp": ftp_data,
        "telnet": telnet_data,
        "smtp": smtp_data,
        "ntlm": ntlm_data,
        "ips": ip_data
    }