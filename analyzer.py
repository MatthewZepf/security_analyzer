from scapy.all import *

# Define a function to analyze packets and write to a file
def packet_handler(packet):
    with open("packets.txt", "a") as file:
        file.write(str(packet.summary()) + "\n")
        file.write(str(packet.show(dump=True)) + "\n")

# Sniff network traffic on a specific interface
sniff(iface="eth0", prn=packet_handler, count=10)  # sniff 10 packets


def main():
    # Sniff network traffic on a specific interface
    sniff(iface="eth0", prn=packet_handler, count=25)  # sniff 10 packets

if __name__ == "__main__":
    main()
