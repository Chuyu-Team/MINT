using System;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace ZwGen
{
    class Program
    {
        public static string GetRepositoryRoot()
        {
            Process process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    FileName = "git.exe",
                    Arguments = "rev-parse --show-toplevel"
                }
            };

            if (process.Start())
            {
                process.WaitForExit();
                if (process.ExitCode == 0)
                {
                    string? result = process.StandardOutput.ReadLine();
                    if (result != null)
                    {
                        return Path.GetFullPath(result);
                    }
                }
            }

            return string.Empty;
        }

        static void Main(string[] args)
        {
            string currentFilePath = GetRepositoryRoot() + @"\Tools\amalgamate\MINT.h";

            string text = File.ReadAllText(currentFilePath);

            Regex regex = new Regex(
                @"NTSYSCALLAPI[\w\s_]*NTAPI\s*(Nt(\w)*)\(.*?\);",
                RegexOptions.Compiled | RegexOptions.Singleline);
            MatchCollection matches;

            matches = regex.Matches(text);

            foreach (Match match in matches)
            {
                string currentName = match.Groups[1].Value;
                string currentText = match.Value;
                int currentNameIndex = match.Groups[1].Index - match.Index;

                string newText = string.Format(
                    "{0}\r\n\r\n{1}Zw{2}", 
                    currentText, 
                    currentText.Substring(0, currentNameIndex), 
                    currentText.Substring(currentNameIndex + 2));
                // Make sure we don't add definitions repeatedly.
                if (text.IndexOf(newText) == -1)
                {
                    text = text.Replace(currentText, newText);
                }
            }

            string outputFile = File.ReadAllText(
                System.AppDomain.CurrentDomain.BaseDirectory + "\\FileTemplate.txt",
                System.Text.Encoding.UTF8);

            outputFile = outputFile.Replace("{FILE_CONTENT}", text);

            File.WriteAllText(
                currentFilePath, 
                outputFile,
                System.Text.Encoding.UTF8);
        }
    }
}
