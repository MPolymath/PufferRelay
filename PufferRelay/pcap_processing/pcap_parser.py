from PufferRelay.protocols import process_ldap, process_http, process_ftp, process_telnet, process_smtp, process_ips, process_ntlm, process_netbios
from PufferRelay.core_imports import logging
from PufferRelay.utils.loading_animation import show_loading_animation
import threading
import time

def parse_pcap(pcap_file):
    """
    Parses a PCAP file and extracts data for LDAP, HTTP, FTP, TELNET, SMTP, NTLM, and IPs.

    Args:
        pcap_file (str): Path to the .pcap file.

    Returns:
        dict: Extracted data categorized by protocol.
    """
    logging.info(f"Parsing PCAP file: {pcap_file}")

    # Initialize loading animation
    update_animation, show_ready = show_loading_animation()
    animation_running = True

    def animation_loop():
        """Run the animation until stopped."""
        while animation_running:
            update_animation()
            time.sleep(0.1)

    # Start loading animation in a separate thread
    animation_thread = threading.Thread(target=animation_loop)
    animation_thread.start()

    try:
        # Process all protocols
        ldap_data = process_ldap(pcap_file)
        http_data = process_http(pcap_file)
        ftp_data = process_ftp(pcap_file)
        telnet_data = process_telnet(pcap_file)
        smtp_data = process_smtp(pcap_file)
        ntlm_data = process_ntlm(pcap_file)
        ip_data = process_ips(pcap_file)
        netbios_data = process_netbios(pcap_file)

        # Stop animation and show ready message
        animation_running = False
        animation_thread.join()
        show_ready()

        return {
            "ldap": ldap_data,
            "http": http_data,
            "ftp": ftp_data,
            "telnet": telnet_data,
            "smtp": smtp_data,
            "ntlm": ntlm_data,
            "ips": ip_data,
            "netbios": netbios_data
        }
    except Exception as e:
        # Ensure animation stops even if there's an error
        animation_running = False
        animation_thread.join()
        raise e