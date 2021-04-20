using System;
using System.Data;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using toolbelt;

namespace rz_report
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 1)
            {
                Parallel.ForEach(args, new ParallelOptions
                {
                    MaxDegreeOfParallelism = Environment.ProcessorCount
                }, (arg) => ShellUtils.RunShellAsync(
                    "dotnet",
                    $"\"{Assembly.GetExecutingAssembly().Location}\" \"{arg}\"")
                    .GetAwaiter().GetResult()
                );
            }
            else if (args.Length == 1)
            {
                string arg = args[0];
                if (File.Exists(arg))
                {
                    using (var rizin = new Rizin())
                    {
                        rizin.Command($"o \"{arg}\"");
                        string fileName = Path.GetFileName(arg);
                        using (DataTable dt = rizin.CommandDataTable("itj"))
                        {
                            if (dt.Columns.Contains(".md5"))
                            {
                                fileName = (string)dt.Rows[0][".md5"];
                            }
                        }

                        string path = $"rz_report/{fileName}";
                        Directory.CreateDirectory(path);

                        Report report = new Report(rizin, path);

                        rizin.CommandAnalyzeBinary();

                        Yara yara = new Yara(rizin, path);
                        yara.TryYaraCheck();

                        report.Hashes();
                        report.Info();

                        if (CheckIsNotExecutable(rizin))
                            return;

                        if (CheckIsCilExecutable(rizin))
                        {
                            try
                            {
                                var decompiler = new CSharpDecompiler(arg, new DecompilerSettings());
                                string code = decompiler.DecompileWholeModuleAsString();
                                string cilFileName = string.Concat(path, Path.DirectorySeparatorChar, "cil.txt");
                                File.WriteAllText(cilFileName, code);
                            }
                            catch (Exception)
                            { }
                            return;
                        }

                        report.Headers();
                        report.Sections();
                        report.Resources();
                        report.Libraries();
                        report.Signature();
                        report.Entrypoints();
                        report.Imports();
                        report.Exports();
                        report.Strings();
                        report.StackStrings();
                        report.Functions();

                        rizin.Command($"Ps \"{path}/project.rzdb\"");

                        // Opcodes opcodes = new Opcodes(rizin, path);
                        // opcodes.Disassemble();

                        Data data = new Data(rizin, path);
                        data.Export();
                    }
                }
            }
            else
            {
                Console.WriteLine(@"usage: rz_report [FILE]...");
                Console.WriteLine(@"creates a folder ""./rz_report"" and writes the analysis " +
                                  @"results inside subfolders named after their MD5 sums.");
            }
        }

        private static bool CheckIsNotExecutable(Rizin rizin)
        {
            using (var json = rizin.CommandJson("aflj"))
            {
                if (json == null || json.RootElement.GetArrayLength() < 1)
                    return true;
            }
            return false;
        }

        private static bool CheckIsCilExecutable(Rizin rizin)
        {
            using (var json = rizin.CommandJson("ij"))
            {
                if (json != null)
                {
                    JsonElement elem = json.RootElement;
                    if (elem.TryGetProperty("bin", out elem))
                    {
                        if (elem.TryGetProperty("lang", out elem))
                        {
                            if (elem.GetString() == "cil")
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }
    }
}
