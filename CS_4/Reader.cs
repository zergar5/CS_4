using System.Text;

namespace CS_4
{
    public class Reader
    {
        public static List<byte> Read(string fileName)
        {
            var bytes = new List<byte>();
            using var streamReader = new FileStream(fileName, FileMode.OpenOrCreate);
            using var binaryReader = new BinaryReader(streamReader, Encoding.ASCII);
            while (binaryReader.PeekChar() > -1)
            {
                bytes.Add(binaryReader.ReadByte());
            }
            return bytes;
        }
    }
}
