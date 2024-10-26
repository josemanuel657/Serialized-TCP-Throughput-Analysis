"""
This script computes the throughput of a pcap file.
"""

import dpkt


def compute_throughput(pcap_file_path):
    # Parses the pcap file and computes the throughput as
    # the total number of bytes divided by the total time
    with open(pcap_file_path, "rb") as file:
        pcap = dpkt.pcap.Reader(file)
        start_time = None
        end_time = None
        total_bytes = 0
        for timestamp, buf in pcap:
            # Filter by port
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data

            if tcp.dport != 5201:
                continue

            if start_time is None:
                start_time = timestamp
            end_time = timestamp
            total_bytes += ip.len

        total_time = end_time - start_time
        throughput = total_bytes / total_time
        return throughput


if __name__ == "__main__":
    pcap_file_path = input("Enter the path to the pcap file: ")
    throughput = compute_throughput(pcap_file_path)
    print(f"Throughput is {throughput / 125000} Mbps")
