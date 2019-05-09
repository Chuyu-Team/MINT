using System;
using System.IO;
using System.Text.RegularExpressions;

namespace ZwGen
{
    class Program
    {
        static void Main(string[] args)
        {
            string currentFilePath = "E:\\Projects\\MINT\\Tools\\amalgamate\\MINT.h";

            string text = File.ReadAllText(currentFilePath);

            Regex regex = new Regex(@"NTSYSCALLAPI[\w\s_]*NTAPI\s*(Nt(\w)*)\(.*?\);", RegexOptions.Compiled | RegexOptions.Singleline);
            MatchCollection matches;

            matches = regex.Matches(text);

            foreach (Match match in matches)
            {
                string currentName = match.Groups[1].Value;
                string currentText = match.Value;
                int currentNameIndex = match.Groups[1].Index - match.Index;

                string newText = currentText + "\r\n\r\n" + currentText.Substring(0, currentNameIndex) + "Zw" + currentText.Substring(currentNameIndex + 2);

                // Make sure we don't add definitions repeatedly.
                if (text.IndexOf(newText) == -1)
                {
                    text = text.Replace(currentText, newText);
                }
            }

            string outputFile = File.ReadAllText(System.AppDomain.CurrentDomain.BaseDirectory + "\\FileTemplate.txt");
            outputFile = outputFile.Replace("{FILE_CONTENT}", text);

            File.WriteAllText(currentFilePath, outputFile);
        }
    }
}
