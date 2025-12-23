using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace DnsDownloader
{
    /// <summary>
    /// DNS Downloader Client - Downloads files over DNS TXT records
    /// C# implementation of dns_downloader.py
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            var options = ParseArguments(args);
            if (options == null)
            {
                PrintUsage();
                return;
            }

            var client = new DnsDownloaderClient(options);
            client.Download();
        }

        static Options ParseArguments(string[] args)
        {
            var options = new Options();
            
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-d":
                    case "--domain":
                        if (i + 1 < args.Length) options.Domain = args[++i];
                        break;
                    case "-p":
                    case "--password":
                        if (i + 1 < args.Length) options.Password = args[++i];
                        break;
                    case "-s":
                    case "--server":
                        if (i + 1 < args.Length) options.DnsServer = args[++i];
                        break;
                    case "-P":
                    case "--port":
                        if (i + 1 < args.Length) options.Port = int.Parse(args[++i]);
                        break;
                    case "-o":
                    case "--output":
                        if (i + 1 < args.Length) options.Output = args[++i];
                        break;
                    case "-t":
                    case "--throttle":
                        if (i + 1 < args.Length) options.ThrottleMs = int.Parse(args[++i]);
                        break;
                    case "-r":
                    case "--retries":
                        if (i + 1 < args.Length) options.Retries = int.Parse(args[++i]);
                        break;
                    case "-h":
                    case "--help":
                        return null;
                }
            }

            if (string.IsNullOrEmpty(options.Domain) || string.IsNullOrEmpty(options.Password))
                return null;

            return options;
        }

        static void PrintUsage()
        {
            Console.WriteLine("DNS Downloader Client - Download files over DNS");
            Console.WriteLine("\nUsage: DnsDownloader -d <domain> -p <password> [options]");
            Console.WriteLine("\nRequired:");
            Console.WriteLine("  -d, --domain      Domain name for DNS requests");
            Console.WriteLine("  -p, --password    Password for decryption");
            Console.WriteLine("\nOptional:");
            Console.WriteLine("  -s, --server      DNS server IP (default: system DNS)");
            Console.WriteLine("  -P, --port        DNS server port (default: 53)");
            Console.WriteLine("  -o, --output      Output file path");
            Console.WriteLine("  -t, --throttle    Delay between requests in ms (default: 0)");
            Console.WriteLine("  -r, --retries     Max retries per chunk (default: 3)");
            Console.WriteLine("  -h, --help        Show this help");
        }
    }

    class Options
    {
        public string Domain { get; set; }
        public string Password { get; set; }
        public string DnsServer { get; set; } = null;
        public int Port { get; set; } = 53;
        public string Output { get; set; } = null;
        public int ThrottleMs { get; set; } = 0;
        public int Retries { get; set; } = 3;
    }

    class DnsDownloaderClient
    {
        private Options options;
        private Random random = new Random();

        public DnsDownloaderClient(Options options)
        {
            this.options = options;
        }

        public void Download()
        {
            Console.WriteLine("[*] DNS Downloader Client");
            Console.WriteLine($"[*] Target domain: {options.Domain}");
            if (!string.IsNullOrEmpty(options.DnsServer))
                Console.WriteLine($"[*] Using DNS server: {options.DnsServer}:{options.Port}");

            // Step 1: Get metadata
            Console.WriteLine("\n[*] Sending INIT request...");
            string initQuery = $"init.{options.Domain}";
            string metadataResponse = DnsQuery(initQuery);

            if (string.IsNullOrEmpty(metadataResponse))
            {
                Console.WriteLine("[!] Failed to get metadata from server");
                return;
            }

            FileMetadata metadata;
            try
            {
                metadata = ParseMetadata(metadataResponse);
                Console.WriteLine($"[+] File: {metadata.Filename}");
                Console.WriteLine($"[+] Total chunks: {metadata.TotalChunks}");
                Console.WriteLine($"[+] Encoding: {metadata.Encoding}");
                Console.WriteLine($"[+] Checksum: {metadata.Checksum}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Failed to parse metadata: {ex.Message}");
                Console.WriteLine($"[!] Response was: {metadataResponse}");
                return;
            }

            // Step 2: Download chunks
            Console.WriteLine("\n[*] Downloading chunks...");
            StringBuilder encodedData = new StringBuilder();

            for (int chunkNum = 0; chunkNum < metadata.TotalChunks; chunkNum++)
            {
                bool success = false;
                int retries = 0;

                while (retries < options.Retries && !success)
                {
                    string nonce = GenerateNonce();
                    string chunkQuery = $"chunk-{chunkNum}.{nonce}.{options.Domain}";
                    string chunkResponse = DnsQuery(chunkQuery);

                    if (!string.IsNullOrEmpty(chunkResponse) && chunkResponse != "ERROR")
                    {
                        encodedData.Append(chunkResponse);
                        success = true;
                    }
                    else
                    {
                        retries++;
                        if (retries < options.Retries)
                            Thread.Sleep(500);
                    }
                }

                if (!success)
                {
                    Console.WriteLine($"\n[!] Failed to download chunk {chunkNum} after {options.Retries} retries");
                    return;
                }

                PrintProgress(chunkNum + 1, metadata.TotalChunks);

                if (options.ThrottleMs > 0)
                    Thread.Sleep(options.ThrottleMs);
            }

            Console.WriteLine($"\n[+] Downloaded {encodedData.Length} bytes of encoded data");

            // Step 3: Decode
            Console.WriteLine("[*] Decoding data...");
            byte[] encryptedData;
            try
            {
                if (metadata.Encoding == "base32")
                    encryptedData = Base32Decode(encodedData.ToString());
                else
                    encryptedData = Base64UrlDecode(encodedData.ToString());
                Console.WriteLine($"[+] Decoded size: {encryptedData.Length} bytes");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Failed to decode data: {ex.Message}");
                return;
            }

            // Step 4: Decrypt (RC4)
            Console.WriteLine("[*] Decrypting data...");
            byte[] decryptedData;
            try
            {
                var rc4 = new RC4(options.Password);
                decryptedData = rc4.Decrypt(encryptedData);
                Console.WriteLine($"[+] Decrypted size: {decryptedData.Length} bytes");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Failed to decrypt data: {ex.Message}");
                return;
            }

            // Step 5: Decompress (ZIP)
            Console.WriteLine("[*] Decompressing data...");
            byte[] fileContent;
            string originalFilename;
            try
            {
                using (var zipStream = new MemoryStream(decryptedData))
                using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Read))
                {
                    if (archive.Entries.Count == 0)
                    {
                        Console.WriteLine("[!] ZIP archive is empty");
                        return;
                    }

                    var entry = archive.Entries[0];
                    originalFilename = entry.Name;

                    using (var entryStream = entry.Open())
                    using (var ms = new MemoryStream())
                    {
                        entryStream.CopyTo(ms);
                        fileContent = ms.ToArray();
                    }
                }
                Console.WriteLine($"[+] Decompressed size: {fileContent.Length} bytes");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Failed to decompress data: {ex.Message}");
                return;
            }

            // Step 6: Verify checksum
            uint calculatedChecksum = CalculateChecksum(fileContent);
            if (calculatedChecksum == metadata.Checksum)
            {
                Console.WriteLine("[+] Checksum verified successfully!");
            }
            else
            {
                Console.WriteLine($"[!] Checksum mismatch! Expected: {metadata.Checksum}, Got: {calculatedChecksum}");
                Console.WriteLine("[?] File may be corrupted, but will save anyway...");
            }

            // Step 7: Save file
            string outputPath = string.IsNullOrEmpty(options.Output) ? originalFilename : options.Output;
            try
            {
                File.WriteAllBytes(outputPath, fileContent);
                Console.WriteLine($"\n[+] File saved successfully: {outputPath}");
                Console.WriteLine($"[+] Size: {fileContent.Length} bytes");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Failed to save file: {ex.Message}");
                return;
            }

            Console.WriteLine("\n[+] Download complete!");
        }

        private FileMetadata ParseMetadata(string response)
        {
            var parts = response.Split('|');
            return new FileMetadata
            {
                Filename = parts[0],
                TotalChunks = int.Parse(parts[1]),
                Encoding = parts[2],
                Checksum = uint.Parse(parts[3])
            };
        }

        private string DnsQuery(string qname)
        {
            try
            {
                if (string.IsNullOrEmpty(options.DnsServer))
                {
                    // Use system DNS resolver
                    return DnsQuerySystem(qname);
                }
                else
                {
                    // Use custom DNS server
                    return DnsQuerySocket(qname, options.DnsServer, options.Port);
                }
            }
            catch (Exception)
            {
                return null;
            }
        }

        private string DnsQuerySystem(string qname)
        {
            // Simple TXT query using nslookup-style approach
            // Note: .NET doesn't have built-in DNS TXT query, so we use UDP socket
            if (string.IsNullOrEmpty(options.DnsServer))
                options.DnsServer = "8.8.8.8"; // Fallback to Google DNS

            return DnsQuerySocket(qname, options.DnsServer, options.Port);
        }

        private string DnsQuerySocket(string qname, string server, int port)
        {
            try
            {
                using (var udpClient = new UdpClient())
                {
                    udpClient.Client.ReceiveTimeout = 10000;
                    
                    // Build DNS query packet
                    byte[] query = BuildDnsQuery(qname);
                    
                    // Send query
                    udpClient.Send(query, query.Length, server, port);
                    
                    // Receive response
                    var remoteEP = new IPEndPoint(IPAddress.Any, 0);
                    byte[] response = udpClient.Receive(ref remoteEP);
                    
                    // Parse TXT record from response
                    return ParseDnsTxtResponse(response);
                }
            }
            catch (Exception)
            {
                return null;
            }
        }

        private byte[] BuildDnsQuery(string qname)
        {
            var query = new List<byte>();
            
            // Transaction ID (random)
            ushort transactionId = (ushort)random.Next(0, 65536);
            query.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)transactionId)));
            
            // Flags: standard query
            query.AddRange(new byte[] { 0x01, 0x00 });
            
            // Questions: 1
            query.AddRange(new byte[] { 0x00, 0x01 });
            
            // Answer RRs: 0
            query.AddRange(new byte[] { 0x00, 0x00 });
            
            // Authority RRs: 0
            query.AddRange(new byte[] { 0x00, 0x00 });
            
            // Additional RRs: 0
            query.AddRange(new byte[] { 0x00, 0x00 });
            
            // QNAME
            foreach (var label in qname.Split('.'))
            {
                query.Add((byte)label.Length);
                query.AddRange(Encoding.ASCII.GetBytes(label));
            }
            query.Add(0x00); // End of QNAME
            
            // QTYPE: TXT (16)
            query.AddRange(new byte[] { 0x00, 0x10 });
            
            // QCLASS: IN (1)
            query.AddRange(new byte[] { 0x00, 0x01 });
            
            return query.ToArray();
        }

        private string ParseDnsTxtResponse(byte[] response)
        {
            try
            {
                // Skip header (12 bytes)
                int pos = 12;
                
                // Skip question section
                while (pos < response.Length && response[pos] != 0)
                {
                    int labelLen = response[pos];
                    pos += labelLen + 1;
                }
                pos += 5; // Skip null terminator + QTYPE + QCLASS
                
                // Parse answer section
                while (pos < response.Length)
                {
                    // Check for compression pointer
                    if ((response[pos] & 0xC0) == 0xC0)
                    {
                        pos += 2; // Skip compression pointer
                    }
                    else
                    {
                        // Skip name
                        while (pos < response.Length && response[pos] != 0)
                        {
                            int labelLen = response[pos];
                            pos += labelLen + 1;
                        }
                        pos++; // Skip null terminator
                    }
                    
                    if (pos + 10 > response.Length) break;
                    
                    // Type
                    ushort rType = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(response, pos));
                    pos += 2;
                    
                    // Class
                    pos += 2;
                    
                    // TTL
                    pos += 4;
                    
                    // Data length
                    ushort dataLen = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(response, pos));
                    pos += 2;
                    
                    // If TXT record (type 16)
                    if (rType == 16)
                    {
                        StringBuilder result = new StringBuilder();
                        int endPos = pos + dataLen;
                        
                        while (pos < endPos)
                        {
                            int txtLen = response[pos++];
                            if (pos + txtLen <= endPos)
                            {
                                result.Append(Encoding.ASCII.GetString(response, pos, txtLen));
                                pos += txtLen;
                            }
                        }
                        
                        return result.ToString();
                    }
                    else
                    {
                        pos += dataLen;
                    }
                }
            }
            catch (Exception)
            {
                // Ignore parsing errors
            }
            
            return null;
        }

        private string GenerateNonce(int length = 8)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        private byte[] Base64UrlDecode(string data)
        {
            // Convert Base64URL to standard Base64
            data = data.Replace('-', '+').Replace('_', '/');
            
            // Add padding
            int padding = 4 - (data.Length % 4);
            if (padding < 4)
                data += new string('=', padding);
            
            return Convert.FromBase64String(data);
        }

        private byte[] Base32Decode(string data)
        {
            data = data.ToUpper().TrimEnd('=');
            
            // Add padding
            int padding = 8 - (data.Length % 8);
            if (padding < 8)
                data += new string('=', padding);
            
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var output = new List<byte>();
            
            for (int i = 0; i < data.Length; i += 8)
            {
                long value = 0;
                int bits = 0;
                
                for (int j = 0; j < 8 && i + j < data.Length; j++)
                {
                    char c = data[i + j];
                    if (c == '=') break;
                    
                    int index = alphabet.IndexOf(c);
                    if (index < 0) throw new FormatException("Invalid Base32 character");
                    
                    value = (value << 5) | (long)index;
                    bits += 5;
                }
                
                while (bits >= 8)
                {
                    bits -= 8;
                    output.Add((byte)((value >> bits) & 0xFF));
                }
            }
            
            return output.ToArray();
        }

        private uint CalculateChecksum(byte[] data)
        {
            uint sum = 0;
            foreach (byte b in data)
                sum += b;
            return sum & 0xFFFFFFFF;
        }

        private void PrintProgress(int current, int total)
        {
            const int barLength = 50;
            int filled = (int)Math.Round((double)barLength * current / total);
            double percent = Math.Round(100.0 * current / total, 1);
            
            string bar = new string('=', filled) + new string('-', barLength - filled);
            Console.Write($"\r[{bar}] {percent}% Chunk {current}/{total}");
        }
    }

    class FileMetadata
    {
        public string Filename { get; set; }
        public int TotalChunks { get; set; }
        public string Encoding { get; set; }
        public uint Checksum { get; set; }
    }

    /// <summary>
    /// RC4 stream cipher implementation
    /// Compatible with Python RC4 implementation
    /// </summary>
    class RC4
    {
        private int[] state = new int[256];
        private int x = 0;
        private int y = 0;

        public RC4(string key)
        {
            // Initialize state
            for (int i = 0; i < 256; i++)
                state[i] = i;
            
            // KSA (Key Scheduling Algorithm)
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (key[i % key.Length] + state[i] + j) & 0xFF;
                Swap(ref state[i], ref state[j]);
            }
            
            x = 0;
            y = 0;
        }

        public byte[] Decrypt(byte[] data)
        {
            byte[] output = new byte[data.Length];
            
            for (int i = 0; i < data.Length; i++)
            {
                x = (x + 1) & 0xFF;
                y = (state[x] + y) & 0xFF;
                Swap(ref state[x], ref state[y]);
                
                int keyByte = state[(state[x] + state[y]) & 0xFF];
                output[i] = (byte)(data[i] ^ keyByte);
            }
            
            return output;
        }

        private void Swap(ref int a, ref int b)
        {
            int temp = a;
            a = b;
            b = temp;
        }
    }
}

