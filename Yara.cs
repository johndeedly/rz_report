using System;
using System.Buffers;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using toolbelt;

namespace rz_report
{
    public class Yara
    {
        Rizin rizin;
        string basePath;

        public Yara(Rizin rizin, string basePath)
        {
            this.rizin = rizin;
            this.basePath = basePath;
        }

        public void TryYaraCheck()
        {
            var outputBuffer = new ArrayBufferWriter<byte>();
            using (var jsonWriter = new Utf8JsonWriter(outputBuffer))
            {
                jsonWriter.WriteStartArray();

                IterateMatches(jsonWriter);

                jsonWriter.WriteEndArray();
            }

            var enc = new UTF8Encoding(false);
            string json = enc.GetString(outputBuffer.WrittenSpan);
            File.WriteAllText($"{basePath}/yara.json", json, enc);

            using (var stream = new FileStream($"{basePath}/yara.csv", FileMode.Create, FileAccess.Write, FileShare.Read))
            using (DataTable dt = new DataTable())
            {
                JsonDocument jdoc = JsonDocument.Parse(json);
                dt.FromJson(jdoc.RootElement);
                dt.ToCsv(stream);
            }
        }

        private void IterateMatches(Utf8JsonWriter jsonWriter)
        {
            try
            {
                List<string> ruleFiles = new();
                if (Directory.Exists("rules"))
                {
                    ruleFiles.AddRange(Directory
                        .EnumerateFiles("rules", "*.yar*", SearchOption.AllDirectories)
                        .OrderBy(x => Path.GetFileName(x))
                        .Where(x => x.EndsWith(".yar") || x.EndsWith(".yara"))
                    );
                }
                string assemblyRules = Path.GetDirectoryName(new Uri(Assembly.GetExecutingAssembly().Location).LocalPath) + "/rules";
                if (Directory.Exists(assemblyRules))
                {
                    ruleFiles.AddRange(Directory
                        .EnumerateFiles(assemblyRules, "*.yar*", SearchOption.AllDirectories)
                        .OrderBy(x => Path.GetFileName(x))
                        .Where(x => x.EndsWith(".yar") || x.EndsWith(".yara"))
                    );
                }
                if (!ruleFiles.Any())
                    return;

                string filePath = null;
                using (var json = rizin.CommandJson("ij"))
                    filePath = json.RootElement.GetProperty("core").GetProperty("file").GetString();
                if (string.IsNullOrWhiteSpace(filePath))
                    return;

                string result = ShellUtils.RunShellTextAsync("yara", $"-s -L -e -w {string.Join(" ", ruleFiles.Select(x => $"\"{x}\""))} \"{filePath}\"").GetAwaiter().GetResult();
                using (var sr = new StringReader(result))
                {
                    int cnt = 0;
                    string line, name = null;
                    while ((line = sr.ReadLine()) != null)
                    {
                        if (line.StartsWith("default:"))
                        {
                            if (name != null)
                            {
                                jsonWriter.WriteEndArray();
                                jsonWriter.WriteEndObject();
                            }
                            name = Regex.Match(line, @"default:(.*?)\s")?.Groups[1]?.Value;
                            jsonWriter.WriteStartObject();
                            jsonWriter.WriteString("match", name);
                            Console.WriteLine($"Yara hit \"{name}\"");
                            jsonWriter.WriteStartArray("hits");
                        }
                        else if (line.StartsWith("0x") && !string.IsNullOrWhiteSpace(name))
                        {
                            Match match = Regex.Match(line, @"(0x[a-f0-9]+)(:[0-9]+)?(:.*?)?[:\s]");
                            if (match.Success)
                            {
                                decimal offset;
                                string length, identifier, mark;
                                ParseMatch(name, match, out offset, out length, out identifier, out mark);

                                decimal? mappedOffset = MapYaraToRizinOffset(offset);
                                string rawdata = null;
                                string rawascii = null;
                                if (mappedOffset.HasValue)
                                {
                                    GetRawData(length, mappedOffset, out rawdata, out rawascii);

                                    MarkInsideRizin(cnt, name, offset, length, identifier, mark, mappedOffset);
                                }

                                WriteJson(jsonWriter, offset, length, identifier, rawdata, rawascii);

                                cnt++;
                            }
                        }
                    }

                    if (name != null)
                    {
                        jsonWriter.WriteEndArray();
                        jsonWriter.WriteEndObject();
                    }
                }
            }
            catch (Exception)
            { }
        }

        private static void ParseMatch(string name, Match match, out decimal offset, out string length, out string identifier, out string mark)
        {
            string soffset = match.Groups[1].Value;
            offset = ulong.Parse(soffset.Substring(2), NumberStyles.HexNumber);
            length = string.Empty;
            if (match.Groups[2].Success)
                length = match.Groups[2].Value.Trim(':');
            if (string.IsNullOrWhiteSpace(length))
                length = "1";

            identifier = string.Empty;
            if (match.Groups[3].Success)
                identifier = match.Groups[3].Value.Replace("$", string.Empty).Trim(':');

            mark = $"loc.yara.{name}";
            if (!string.IsNullOrWhiteSpace(identifier))
                mark = $"{mark}.{identifier}";
        }

        private void GetRawData(string length, decimal? mappedOffset, out string rawdata, out string rawascii)
        {
            using (var json = rizin.CommandJson($"pcj {length} @ {mappedOffset}"))
            {
                var root = json.RootElement;
                var len = root.GetArrayLength();
                StringBuilder hex = new StringBuilder(len * 2);
                StringBuilder asc = new StringBuilder(len);
                foreach (byte b in root.EnumerateArray().Select(x => x.GetByte()))
                {
                    hex.AppendFormat("{0:x2}", b);
                    if (b >= 32 && b < 127)
                        asc.Append((char)b);
                    else
                        asc.Append('.');
                }
                rawdata = hex.ToString();
                rawascii = asc.ToString();
            }
        }

        private void MarkInsideRizin(int cnt, string name, decimal offset, string length, string identifier, string mark, decimal? mappedOffset)
        {
            rizin.Command("fs+yara");
            rizin.Command($"f {mark}.{cnt} {length} @{mappedOffset}");
            rizin.Command($"fC {mark}.{cnt} 'Yara match \"{name}\" at \"{offset}\" lenght \"{length}\" identifier \"{identifier}\"'");
            rizin.Command("fs-");
        }

        private static void WriteJson(Utf8JsonWriter jsonWriter, decimal offset, string length, string identifier, string rawdata, string rawascii)
        {
            jsonWriter.WriteStartObject();
            jsonWriter.WriteNumber("offset", offset);
            jsonWriter.WriteString("length", length);
            jsonWriter.WriteString("identifier", identifier);
            if (!string.IsNullOrWhiteSpace(rawdata))
            {
                jsonWriter.WriteString("raw", rawdata);
                jsonWriter.WriteString("ascii", rawascii);
            }
            jsonWriter.WriteEndObject();
        }

        private decimal? MapYaraToRizinOffset(decimal offset)
        {
            try
            {
                using (var json = rizin.CommandJson("iSj"))
                {
                    foreach (var elem in json.RootElement.EnumerateArray())
                    {
                        decimal paddr = elem.GetProperty("paddr").GetDecimal();
                        decimal vaddr = elem.GetProperty("vaddr").GetDecimal();
                        decimal psize = elem.GetProperty("size").GetDecimal();
                        if (paddr <= offset && paddr + psize > offset)
                        {
                            decimal mappedOffset = vaddr + offset - paddr;
                            return mappedOffset;
                        }
                    }
                }
            }
            catch (Exception)
            { }
            return null;
        }
    }
}