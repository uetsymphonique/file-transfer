using System;
using System.IO;
using System.Net.NetworkInformation;
using System.Text;

namespace ICMPTransferTools
{
    internal static class InvokeIcmpDownload
    {
        private const int TimeoutMs = 1000;

        private static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: InvokeIcmpDownload <ip> <outputFile>");
                return;
            }

            string ipAddress = args[0];
            string outputPath = args[1];

            var ping = new Ping();
            var options = new PingOptions { DontFragment = true };

            Console.WriteLine("Downloading file, please wait...");

            using var fs = new FileStream(outputPath, FileMode.Append, FileAccess.Write, FileShare.Read);

            while (true)
            {
                byte[] payload = Array.Empty<byte>();
                PingReply reply = ping.Send(ipAddress, TimeoutMs, payload, options);

                if (reply?.Status != IPStatus.Success || reply.Buffer == null)
                {
                    continue;
                }

                string response = Encoding.ASCII.GetString(reply.Buffer);

                if (response == "done")
                {
                    Console.WriteLine("File transfer complete; EXITING.");
                    break;
                }

                fs.Write(reply.Buffer, 0, reply.Buffer.Length);
                fs.Flush();
            }
        }
    }
}

