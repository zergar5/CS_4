using System.Text;

namespace CS_4
{
    public class FrameChecker
    {
        private int _byteNumber;
        private readonly List<byte> _bytes;
        private readonly Dictionary<string, int> _frames;
        private readonly Dictionary<string, int> _protocols;
        private readonly List<string> _result;

        public FrameChecker(List<byte> bytes)
        {
            _byteNumber = 0;
            _bytes = bytes;
            _frames = new Dictionary<string, int>
            {
                { "Ethernet DIX", 0 },
                { "Ethernet Raw 802.3", 0 },
                { "Ethernet SNAP", 0 },
                { "Ethernet LLC", 0 }
            };

            _protocols = new Dictionary<string, int>
            {
                { "IPv4", 0 },
                { "ARP", 0 }
            };
            _result = new List<string>();
        }
        public List<string> Check()
        {
            var size = new StringBuilder();
            size.AppendLine($"Size of file: {_bytes.Count}");
            size.AppendLine();
            size.Append("--------------------------------------------------------");

            _result.Add(size.ToString());
            while (_byteNumber < _bytes.Count)
            {
                var frame = new StringBuilder();

                frame.AppendLine($"Number of frame: {_frames.Values.Sum() + 1}");

                frame.Append("Destination MAC address: ");
                PrintMACAdress(frame);

                frame.Append("Source MAC address: ");
                PrintMACAdress(frame);

                var LT = (_bytes[_byteNumber++] << 8) + _bytes[_byteNumber++];

                CheckFrame(LT, frame);
            }
            _result.Add(TotalInfo());
            return _result;
        }

        public string TotalInfo()
        {
            var total = new StringBuilder();
            var totalCount = _frames.Values.Sum();

            total.AppendLine($"Total number of frames: {totalCount}");
            total.AppendLine("Frame types:");
            total.AppendLine($"Ethernet DIX: {_frames["Ethernet DIX"]}");
            total.AppendLine($"Ethernet Raw 802.3: {_frames["Ethernet Raw 802.3"]}");
            total.AppendLine($"Ethernet SNAP: {_frames["Ethernet SNAP"]}");
            total.AppendLine($"Ethernet LLC: {_frames["Ethernet LLC"]}");
            total.AppendLine("Protocol types:");
            total.AppendLine($"IPv4: {_protocols["IPv4"]}");
            total.Append($"ARP: {_protocols["ARP"]}");

            return total.ToString();
        }

        public void PrintMACAdress(StringBuilder frame)
        {
            for (int i = 0; i < 6; i++, _byteNumber++)
            {
                frame.AppendFormat($"{_bytes[_byteNumber]:X2}");
                frame.Append(':');
            }
            frame.Remove(frame.Length - 1, 1);
            frame.AppendLine();
        }

        public void PrintIPAdress(StringBuilder frame, int protocolByteNumber)
        {
            for (var i = 0; i < 4; i++, protocolByteNumber++)
            {
                frame.Append(_bytes[protocolByteNumber]);
                frame.Append('.');
            }
            frame.Remove(frame.Length - 1, 1);
            frame.AppendLine();
        }

        public void PrintARPAdress(StringBuilder frame, int LEN, int protocolByteNumber)
        {
            for (var i = 0; i < LEN - 1; i++, protocolByteNumber++)
            {
                frame.Append(_bytes[protocolByteNumber]);
                frame.Append(':');
            }
            frame.Remove(frame.Length - 1, 1);
            frame.AppendLine();
        }

        public void CheckFrame(int LT, StringBuilder frame)
        {
            if (LT > 0x05DC)
            {
                _frames["Ethernet DIX"]++;
                frame.AppendLine("Frame type: Ethernet DIX");
                CheckProtocol(LT, frame);
            }
            else
            {
                var LLC = (_bytes[_byteNumber] << 8) + _bytes[_byteNumber + 1];

                switch (LLC)
                {
                    case 0xFFFF:
                        frame.AppendLine("Frame type: Ethernet Raw 802.3");
                        _frames["Ethernet Raw 802.3"]++;
                        break;
                    case 0xAAAA:
                        frame.AppendLine("Frame type: Ethernet SNAP");
                        _frames["Ethernet SNAP"]++;
                        break;
                    default:
                        frame.AppendLine("Frame type: Ethernet LLC");
                        _frames["Ethernet LLC"]++;
                        break;
                }

                _byteNumber += LT;
            }
            
            frame.Append("--------------------------------------------------------");
            _result.Add(frame.ToString());
        }

        public void CheckProtocol(int LT, StringBuilder frame)
        {
            switch (LT)
            {
                case 0x0800:
                    frame.AppendLine("Protocol type: IPv4");
                    _protocols["IPv4"]++;

                    var protocolByteNumber = _byteNumber;

                    var version = (_bytes[protocolByteNumber] & 0xF0) >> 4;
                    frame.AppendLine($"Version: {version}");

                    var headerSize = (_bytes[protocolByteNumber] & 0x0F) * 4;
                    frame.AppendLine($"Header size: {headerSize} ");

                    protocolByteNumber += 2;
                    var frameSize = (_bytes[protocolByteNumber++] << 8) + _bytes[protocolByteNumber++];
                    frame.AppendLine($"Frame size: {frameSize} ");

                    protocolByteNumber += 5;
                    frame.AppendLine(_bytes[protocolByteNumber] == 6 ? "Protocol: TCP" : "Protocol: UDP");

                    protocolByteNumber += 3;
                    frame.Append("Source IP address: ");
                    PrintIPAdress(frame, protocolByteNumber);

                    frame.Append("Destination IP address: ");
                    PrintIPAdress(frame, protocolByteNumber);

                    frame.Append("Data: ");
                    for (var i = 0; i < frameSize - headerSize; i++, protocolByteNumber++)
                    {
                        frame.AppendFormat($"{_bytes[protocolByteNumber]:X2}");
                    }

                    frame.AppendLine();

                    if (frameSize < 46)
                    {
                        _byteNumber += 46;
                    }
                    else
                    {
                        _byteNumber += frameSize;
                    }
                    break;

                case 0x0806:
                    _protocols["ARP"]++;
                    protocolByteNumber = _byteNumber;

                    var HTYPE = (_bytes[protocolByteNumber++] << 8) + _bytes[protocolByteNumber++];
                    if (HTYPE == 0x0001)
                    {
                        frame.AppendLine("Hardware type: Ethernet");
                    }
                    else
                    {
                        frame.AppendLine($"Hardware type : {HTYPE}");
                    }

                    var PTYPE = (_bytes[protocolByteNumber++] << 8) + _bytes[protocolByteNumber++];

                    if (PTYPE == 0x0800)
                    {
                        frame.AppendLine("Protocol type: IPv4");
                    }
                    else
                    {
                        frame.AppendLine($"Protocol type : {PTYPE}");
                    }

                    var HLEN = _bytes[protocolByteNumber++];
                    frame.AppendLine($"Hardware length: {HLEN}");

                    var PLEN = _bytes[protocolByteNumber++];
                    frame.AppendLine($"Protocol length: {PLEN}");

                    var Operation = (_bytes[protocolByteNumber++] << 8) + _bytes[protocolByteNumber++];
                    frame.Append("Operation");

                    frame.AppendLine(Operation == 1 ? "Request" : "Reply");


                    frame.Append("Sender hardware address: ");
                    PrintARPAdress(frame, HLEN, protocolByteNumber);

                    frame.Append("Sender protocol address: ");
                    PrintARPAdress(frame, PLEN, protocolByteNumber);

                    frame.Append("Target hardware address: ");
                    PrintARPAdress(frame, HLEN, protocolByteNumber);

                    frame.Append("Target protocol address: ");
                    PrintARPAdress(frame, PLEN, protocolByteNumber);

                    if (protocolByteNumber - _byteNumber < 46)
                    {
                        _byteNumber += 46;
                    }
                    break;
                default:
                    frame.AppendLine("Protocol type: Unknown");
                    frame.AppendFormat($"Protocol number: {LT:X4}");
                    frame.AppendLine();
                    break;
            }
        }
    }
}
