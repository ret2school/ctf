#!/usr/bin/python

import base64
import struct
import pcapy
import impacket.ImpactDecoder as Decoders
import impacket.ImpactPacket as Packets
from impacket.dns import DNS
from Crypto.Cipher import AES

pattern = 0x08080404
key = b"U\n\xe2\x988\xb3\xdc(X\rl\x0f\xf1\x96\xde\xb2\x0e3\xaf[\xf1\x9f\xe0\x16\x1e\x0b\xa9x\x00fp\xe8"

pcap = pcapy.open_offline("the_compromise/traffic.pcap")
CLIENT_IP = '192.168.111.6'

def decrypt(data):
    aeskey = key[0:16]
    iv = b"abcdefghijklmnop"
    aes = AES.new(aeskey, AES.MODE_CBC, iv)
    return aes.decrypt(data[:-16])

def get_int_raw_resp(dns_resp: DNS):
    data = dns_resp.get_body_as_string()
    
    offset   = 0
    qdcount = dns_resp.get_qdcount()
    for _ in range(qdcount): # number of questions
        offset, qname = dns_resp.parseCompressedMessage(data, offset)
        qtype  = data[offset:offset+2]
        offset  += 2
        qclass = data[offset:offset+2]
        offset  += 2
        qtype  = struct.unpack("!H", qtype)[0]
        qclass = struct.unpack("!H", qclass)[0]

    offset, _ = dns_resp.parseCompressedMessage(data, offset)
    qtype  = data[offset:offset+2]
    qtype  = struct.unpack("!H", qtype)[0]
    offset  += 2

    qclass = data[offset:offset+2]
    qclass = struct.unpack("!H", qclass)[0]
    offset  += 2

    qttl_raw = data[offset:offset+4]
    qttl = struct.unpack("!L", qttl_raw)[0]
    offset  += 4

    qrdlength = data[offset:offset+2]
    qrdlength = struct.unpack("!H", qrdlength)[0]
    offset  += 2

    return qtype, data[offset:offset+qrdlength]

def get_next_dns_pkt():
    ethernet_decoder = Decoders.EthDecoder()
    ip_decoder = Decoders.IPDecoder()

    hdr = True
    packets = 0

    while hdr is not None:
        hdr, body = pcap.next()
        eth = ethernet_decoder.decode(body)
        if eth.get_ether_type() != Packets.IP.ethertype:
            continue
        ip = ip_decoder.decode(eth.get_data_as_string())
        if CLIENT_IP not in [ip.get_ip_src(), ip.get_ip_dst()]:
            continue
        if ip.get_ip_p() != Packets.UDP.protocol:
            continue
        udp = ip_decoder.udp_decoder.decode(ip.get_data_as_string())
        if udp.get_uh_dport() != 53 and udp.get_uh_sport() != 53:
            continue
        if b"thedarkestside\x03org" not in body:
            continue
        dns = DNS(udp.get_data_as_string())
        if (dns.get_flags() & 0x8000) == 0:
            continue
        packets += 1
        if packets < 2:
            continue
        yield (ip.get_ip_src(), ip.get_ip_dst(), dns)

pkts = get_next_dns_pkt()
while True:
    buffer = b""
    (src, dst, dns) = next(pkts)
    qry = dns.get_questions()[0]
    qry_array = qry[0].split(b".")
    if qry_array[0] == b"api":
        # base64 sent information
        type, rawdata = get_int_raw_resp(dns)
        if type == 1:
            buflen = struct.unpack("!L", rawdata)[0] ^ pattern
        trunc = buflen
        while buflen > 0:
            src, dst, resp = next(pkts)
            type, rawdata = get_int_raw_resp(resp)
            rawdata = base64.b64decode(rawdata)
            buflen -= len(rawdata)
            buffer += rawdata
        buffer = buffer[:trunc]
        print(decrypt(buffer))
    elif qry_array[0] == b"cdn":
        type, rawdata = get_int_raw_resp(resp)
        if type == 1:
            buflen = struct.unpack("!L", rawdata)[0] ^ pattern
            while len(buffer) < buflen:
                src, dst, resp = next(pkts)
                type, rawdata = get_int_raw_resp(resp)
                buffer += rawdata
            print(decrypt(buffer))
    elif qry_array[0] == b"post":
        alen = qry_array[1]
        len_chunk = int(str(alen[1:], "ascii"), 16)
        while len(buffer) < len_chunk:
            (src, dst, dns) = next(pkts)
            qry = dns.get_questions()[0]
            qry_array = qry[0].split(b".")
            num_chunks = qry_array[1][0]
            num_chunks -= 0x30
            buffer += bytes.fromhex(str(qry_array[1][1:], 'ascii'))
            if num_chunks >= 2:
                buffer += bytes.fromhex(str(qry_array[2], 'ascii'))
            if num_chunks == 3:
                buffer += bytes.fromhex(str(qry_array[3], 'ascii'))
        print(decrypt(buffer))