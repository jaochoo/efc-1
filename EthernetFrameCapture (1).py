import socket
import struct
import textwrap
import codecs


#   +-----------------------------------------------------+
#   |             Destination MAC Address                  |
#   |                      (6 bytes)                       |
#   +-----------------------------------------------------+
#   |                Source MAC Address                    |
#   |                      (6 bytes)                       |
#   +-----------------------------------------------------+
#   |            Ethernet Type (IPv4, ARP, etc.)           |
#   |                      (2 bytes)                       |
#   +-----------------------------------------------------+
#   |                  Payload (46-1500 bytes)             |
#   +-----------------------------------------------------+
#   |             Frame Check Sequence (FCS)               |
#   |                      (4 bytes)                       |
#   +-----------------------------------------------------+
# ! Specify the data should be unpacked as network byte order (big-endian)
# First 6s for destination MAC Address
# Second 6s for Source MAC Address
# H (2 bytes) for Ethernet Type
# The rest from byte 14 for Payload

def EthernetFrame(rawData):
    destinationAddress, sourceAddress, protocol = struct.unpack(
        '! 6s 6s H', rawData[:14])
    return MacAddress(destinationAddress), MacAddress(sourceAddress), socket.htons(protocol), rawData[14:]


#   +-----------------------------------------------------+
#   |Version|  IHL  |Type of Service|       Total Length   |
#   |  (4)  | (4)   |      (8)      |          (16)        |
#   +-----------------------------------------------------+
#   |               Identification                        |
#   |                      (16)                           |
#   +-----------------------------------------------------+
#   |Flags|    Fragment Offset      |   Time to Live (TTL) |
#   | (3) |          (13)           |          (8)         |
#   +-----------------------------------------------------+
#   |         Protocol            |      Header Checksum  |
#   |           (8)               |           (16)         |
#   +-----------------------------------------------------+
#   |                  Source IP Address                   |
#   |                      (32)                           |
#   +-----------------------------------------------------+
#   |               Destination IP Address                 |
#   |                      (32)                           |
#   +-----------------------------------------------------+
#   |                    Options (if any)                  |
#   +-----------------------------------------------------+
#   |                   Payload Data                       |
#   +-----------------------------------------------------+
# VersionHederLength is a first byte of the IPv4 packet
# version get from the first 4 bits of the VersionHederLength by shift 4 bits to the right
# headerLength get from bitwise with 15 (00001111) then multiply that value with 4
# 8x skip first 8 bytes
# B B mean unpacked as unsigned integers for TTL and Protocol
# 2x skip for 2 bytes
# 4 bytes for source address and destination address
# and the rest are Payload Data

def IPv4Packet(rawData):
    versionHeaderLength = rawData[0]
    version = versionHeaderLength >> 4
    headerLength = (versionHeaderLength & 15) * 4
    TTL, protocol, sourceAddress, destinationAddress = struct.unpack(
        '! 8x B B 2x 4s 4s', data[:20])
    return version, headerLength, TTL, protocol, IPv4Address(sourceAddress), IPv4Address(destinationAddress), data[headerLength]

#   +---------------------+---------------------+---------------------+
#   |     Type (8 bits)    |    Code (8 bits)     |      Checksum       |
#   +---------------------+---------------------+---------------------+
#   |                Identifier (16 bits)         |   Sequence Number   |
#   +---------------------+---------------------+---------------------+
#   |                 Data (variable)                                   |
#   +-------------------------------------------------------------------+
# B B mean unpacked as unsigned integers for ICMP type and Code
# H is 2 bytes unsighed short for checksum


def ICMPPacket(rawData):
    ICMPType, code, checkSum = struct.unpack('! B B H', rawData[:4])
    return ICMPType, code, checkSum, rawData[:4]

#   +---------------------+---------------------+---------------------+
#   |         Source Port (16 bits) |  Destination Port (16 bits)     |
#   +---------------------+---------------------+---------------------+
#   |                       Sequence Number (32 bits)                 |
#   +---------------------+---------------------+---------------------+
#   |                   Acknowledgment Number (32 bits)               |
#   +---------------------+---------------------+---------------------+
#   | Data Offset (4 bits) | Reserved (6 bits)| Control Bits (6 bits) |
#   +---------------------+---------------------+---------------------+
#   |                       Window Size (16 bits)                     |
#   +---------------------+---------------------+---------------------+
#   |                      Checksum (16 bits)                         |
#   +---------------------+---------------------+---------------------+
#   |                     Urgent Pointer (16 bits)                    |
#   +---------------------+---------------------+---------------------+
#   |                     Options (if present)                        |
#   +---------------------+---------------------+---------------------+
#   |                     Data (if present)                           |
#   +---------------------+---------------------+---------------------+


def TCPSegment(rawData):
    (sourcePort, destinationPort, sequence, ackowledgement,
     offsetReverseFlag) = struct.unpack('! H H L L H', rawData[:14])

    # extract offset value (first 4 bits) then shift for 12 bits to get rid of Reserved and Control bits, and multiply by 4
    # offset = 5 * 4 = 20
    offset = (offsetReverseFlag >> 12) * 4

    # extract FIN flag (bit 0)
    # FIN = 0b0000000000000001 (1)
    FIN = offsetReverseFlag & 1

    # extract SYN flag (bit 1)
    # SYN = (offsetReverseFlag & 0b0000000000000010) >> 1
    # SYN = 0b0000000000000001 (1)
    SYN = (offsetReverseFlag & 2) >> 1

    # extract RST flag (bit 2)
    # RST = (offsetReverseFlag & 0b0000000000000100) >> 2
    # RST = 0b0000000000000001 (1)
    RST = (offsetReverseFlag & 4) >> 2

    # extract PSH flag (bit 3)
    # PSH = (offsetReverseFlag & 0b0000000000001000) >> 3
    # PSH = 0b0000000000000001 (1)
    PSH = (offsetReverseFlag & 8) >> 3

    # extract ACK flag (bit 4)
    # ACK = (offsetReverseFlag & 0b0000000000010000) >> 4
    # ACK = 0b0000000000000001 (1)
    ACK = (offsetReverseFlag & 16) >> 4

    # extract URG flag (bit 5)
    # URG = (offsetReverseFlag & 0b0000000000100000) >> 5
    # URG = 0b0000000000000001 (1)
    URG = (offsetReverseFlag & 32) >> 5

    return sourcePort, destinationPort, sequence, ackowledgement, FIN, SYN, RST, PSH, ACK, URG, rawData[offset:]

#    +---------------------+---------------------+---------------------+
#    |           Source Port (16 bits) |  Destination Port (16 bits)   |
#    +---------------------+---------------------+---------------------+
#    |                       Length (16 bits)                          |
#    +---------------------+---------------------+---------------------+
#    |                      Checksum (16 bits)                         |
#    +---------------------+---------------------+---------------------+
#    |                     Data (if present)                           |
#    +---------------------+---------------------+---------------------+
# 2 bytes for source port and destination port
# 2x skip for 2 bytes
# 2 bytes for size


def UDPSegment(rawData):
    sourcePort, destinationPort, size = struct.unpack(
        '! H H 2x H', rawData[:8])
    return sourcePort, destinationPort, size, rawData[:8]


# Seperate ip by adding '.' in between

def IPv4Address(byteAddress):
    return '.'.join(map(str, byteAddress))


# Seperate ip by adding ':' in between sequence of 2 and upper case

def MacAddress(byteAddress):
    return ':'.join(map('{:02x}'.format, byteAddress)).upper()


# This function is for when hexstring passed it will convert the possible hexstring to an UTF-8 character if not possible set it as '-'
# By checking a pair of hexstring then convert them to binary form then concat it together

def lineFormatter(prefix, string, size=80):
    size -= len(prefix)
    if not isinstance(string, (str, bytes)):
        raise TypeError("'string' argument must be a string or a bytes object")
    if isinstance(string, bytes):
        string = ''.join('{:02x}'.format(byte) for byte in string)
    hex_pairs = [string[i:i + 2] for i in range(0, len(string), 2)]
    decoded_chars = []
    for hex_pair in hex_pairs:
        try:
            binary_str = bytes.fromhex(hex_pair)
            decoded_chars.append(codecs.decode(binary_str, 'utf-8'))
        except:
            decoded_chars.append('-')
    decodedString = ''.join(decoded_chars)
    return '\n'.join([prefix + line for line in textwrap.wrap(decodedString, size)])


Socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

while True:
    rawData, address = Socket.recvfrom(65536)
    destinationAddress, sourceAddress, protocol, data = EthernetFrame(rawData)

    # Ethernet Frame
    print("\n---------------------------------| Ethernet Frame: |---------------------------------")
    print("\t  | Destination: {}  | Source: {}  |".format(
        destinationAddress, sourceAddress))
    print("\t  |_________________________________|____________________________|\n")

    # IPv4 Packet
    if protocol == 8:
        (version, headerLength, TTL, protocol, sourceAddress,
         destinationAddress, data) = IPv4Packet(rawData)
        print("\t\t   IPv4 Packet\n")
        print("\t\t      Version: {} \n\t\t      Header Length: {} \n\t\t      Time to Live: {}\n".format(
            version, headerLength, TTL))

    # ICMP Packet
    if protocol == 1:
        ICMPType, code, checksum, data = ICMPPacket(rawData)
        print("\t\t   ICMP Packet\n")
        print("\t\t      Type: {} \n\t\t      Code: {} \n\t\t      Checksum: {}\n".format(
            ICMPType, code, checksum))
        print("\t\t      Data:\n")
        print(lineFormatter("\t\t      ", data))

    # TCP Segment
    if protocol == 6:
        (sourcePort, destinationPort, sequence, ackowledgement, FIN,
         SYN, RST, PSH, ACK, URG, data) = TCPSegment(rawData)
        print("\t\t   TCP Segment\n")
        print("\t\t      Source Port: {} \n\t\t      Destination Port: {}".format(
            sourcePort, destinationPort))
        print("\t\t      Sequence: {} \n\t\t      Acknowledge: {}\n".format(
            sequence, ackowledgement))
        print("\t\t      FLAG\n")
        print("\t\t         URG: {} \n\t\t         ACK: {} \n\t\t         PSH: {} \n\t\t         RST: {} \n\t\t         SYN: {} \n\t\t         FIN: {}\n".format(
            URG, ACK, PSH, RST, SYN, FIN))
        print("\t\t      Data:\n")
        print(lineFormatter("\t\t      ", data))

    # UDP Segment
    if protocol == 17:
        sourcePort, destinationPort, length, data = UDPSegment(rawData)
        print("\t\t   UDP Segment\n")
        print("\t\t      Source Port: {} \n\t\t      Destination Port: {} \n\t\t      Length: {}\n".format(
            sourcePort, destinationPort, length))

    # Other Data
    if protocol != 17 and protocol != 6 and protocol != 8 and protocol != 1:
        print("\t\t      Data\n")
        print(lineFormatter("\t\t      ", data))

    print("\n-------------------------------------------------------------------------------------\n")
