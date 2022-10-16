namespace CS_4
{
    public class Writer
    {
        public static void Write(List<string> result, string fileName)
        {
            using var streamReader = new FileStream(fileName, FileMode.OpenOrCreate);
            using var streamWriter = new StreamWriter(streamReader);

            foreach (var item in result)
            {
                streamWriter.WriteLine(item);
            }
            Console.WriteLine(result[^1]);
        }
    }
}
