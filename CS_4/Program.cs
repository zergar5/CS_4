using CS_4;

Console.Write("Write file name: ");
var fileName = Console.ReadLine();
Console.WriteLine();
var bytes = Reader.Read(fileName);
var frameChecker = new FrameChecker(bytes);
var result = frameChecker.Check();
Writer.Write(result, "output.txt");