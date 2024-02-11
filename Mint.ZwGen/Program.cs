using Mile.Project.Helpers;
using System.Text.RegularExpressions;

namespace Mint.ZwGen
{
    internal class Program
    {
        private static readonly Regex NtApiRegex = new Regex(
            @"NTSYSCALLAPI[\w\s_]*NTAPI\s*(Nt(\w)*)\(.*?\);",
            RegexOptions.Compiled | RegexOptions.Singleline);

        private static readonly Regex ZwApiRegex = new Regex(
            @"NTSYSCALLAPI[\w\s_]*NTAPI\s*(Zw(\w)*)\(.*?\);",
            RegexOptions.Compiled | RegexOptions.Singleline);

        private static string RepositoryRoot = GitRepository.GetRootPath();

        static void Main(string[] args)
        {
            DirectoryInfo Folder = new DirectoryInfo(
                RepositoryRoot + @"\Mint\Mint.Implementation");

            foreach (FileInfo FileItem in Folder.GetFiles())
            {
                if (FileItem.Extension.ToLower() != ".h")
                {
                    continue;
                }

                string Content = File.ReadAllText(FileItem.FullName);

                foreach (Match MatchItem in ZwApiRegex.Matches(Content))
                {
                    Content = Content.Replace(
                        "\r\n\r\n" + MatchItem.Value,
                        string.Empty);
                }

                foreach (Match MatchItem in NtApiRegex.Matches(Content))
                {
                    string CurrentName =
                        MatchItem.Groups[1].Value;
                    string CurrentText =
                        MatchItem.Value;
                    int CurrentNameIndex =
                        MatchItem.Groups[1].Index - MatchItem.Index;

                    string NewText = string.Format(
                        "{0}\r\n\r\n{1}Zw{2}",
                        CurrentText,
                        CurrentText.Substring(0, CurrentNameIndex),
                        CurrentText.Substring(CurrentNameIndex + 2));

                    // Make sure we don't add definitions repeatedly.
                    if (Content.IndexOf(NewText) == -1)
                    {
                        Content = Content.Replace(CurrentText, NewText);
                    }
                }

                FileUtilities.SaveTextToFileAsUtf8Bom(FileItem.FullName, Content);
            }
            
            Console.WriteLine("Mint.ZwGen task has been completed.");
            Console.ReadKey();
        }
    }
}
