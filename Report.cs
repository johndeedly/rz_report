using System;
using System.Buffers;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using toolbelt;

namespace rz_report
{
    public class Report
    {
        Rizin rizin;
        string basePath;

        public Report(Rizin rizin, string basePath)
        {
            this.rizin = rizin;
            this.basePath = basePath;
        }

        private void Generate(string cmd, string fileName, bool yx = false)
        {
            using (var json = rizin.CommandJson(cmd))
            {
                Generate(json, fileName, yx);
            }
        }

        private void Generate(JsonDocument json, string fileName, bool yx = false)
        {
            if (json == null)
                return;
            using (var stream = new FileStream($"{basePath}/{fileName}.json", FileMode.Create, FileAccess.Write, FileShare.Read))
            using (var writer = new Utf8JsonWriter(stream))
            {
                json.WriteTo(writer);
            }
            using (var stream = new FileStream($"{basePath}/{fileName}.csv", FileMode.Create, FileAccess.Write, FileShare.Read))
            using (DataTable dt = new DataTable())
            {
                dt.FromJson(json.RootElement);
                if (yx)
                    dt.ToCsvTransposed(stream);
                else
                    dt.ToCsv(stream);
            }
        }

        public void Hashes()
        {
            var outputBuffer = new ArrayBufferWriter<byte>();
            using (var jsonWriter = new Utf8JsonWriter(outputBuffer))
            {
                jsonWriter.WriteStartObject();
                using (var json = rizin.CommandJson("itj"))
                {
                    foreach (var elem in json.RootElement.EnumerateObject())
                    {
                        elem.WriteTo(jsonWriter);
                    }
                }
                TryAddSsdeepHash(jsonWriter);
                jsonWriter.WriteEndObject();
            }
            using (var json = JsonDocument.Parse(Encoding.UTF8.GetString(outputBuffer.WrittenSpan)))
            {
                Generate(json, "hashes", true);
            }
        }

        private bool TryAddSsdeepHash(Utf8JsonWriter jsonWriter)
        {
            try
            {
                string filePath = null;
                using (var json = rizin.CommandJson("ij"))
                {
                    filePath = json.RootElement.GetProperty("core").GetProperty("file").GetString();
                }
                if (!string.IsNullOrWhiteSpace(filePath))
                {
                    string data = ShellUtils.RunShellTextAsync("ssdeep", $"-c \"{filePath}\"")
                        .GetAwaiter()
                        .GetResult();
                    string hash = data.Split('\n')[1].Split(',').First();
                    jsonWriter.WriteString("ssdeep", hash);
                }
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }

        public void Info()
        {
            Generate("ij", "info", true);
        }

        public void Entrypoints()
        {
            var outputBuffer = new ArrayBufferWriter<byte>();
            using (var json1 = rizin.CommandJson("iej"))
            using (var json2 = rizin.CommandJson("ieej"))
            using (var jsonWriter = new Utf8JsonWriter(outputBuffer))
            {
                jsonWriter.WriteStartArray();
                if (json1 != null)
                {
                    foreach (var elem in json1.RootElement.EnumerateArray())
                    {
                        elem.WriteTo(jsonWriter);
                    }
                }
                if (json2 != null)
                {
                    foreach (var elem in json2.RootElement.EnumerateArray())
                    {
                        elem.WriteTo(jsonWriter);
                    }
                }
                jsonWriter.WriteEndArray();
            }
            using (var json = JsonDocument.Parse(Encoding.UTF8.GetString(outputBuffer.WrittenSpan)))
            {
                Generate(json, "entrypoints");
            }
        }

        public void Headers()
        {
            Generate("ihj", "headers");
        }

        public void Sections()
        {
            Generate("iSj entropy,md5,sha1,sha256", "sections");
        }

        public void Resources()
        {
            Generate("iRj", "resources");
        }

        public void Libraries()
        {
            Generate("ilj", "libraries");
        }

        public void Imports()
        {
            Generate("iij", "imports");
        }

        public void Exports()
        {
            Generate("iEj", "exports");
        }

        public void Signature()
        {
            Generate("iCj", "signature");
        }

        public void Strings()
        {
            Generate("izj", "strings");
        }

        public void Functions()
        {
            Generate("aflj", "functions");
        }

        private static string backslash = "\\";
        private static string doublebackslash = "\\\\";
        private static string mark = "'";
        private static string markescaped = "\\'";

        private JsonDocument GetStackStringsJson()
        {
            var outputBuffer = new ArrayBufferWriter<byte>();
            int cnt = 0;
            using (var jsonWriter = new Utf8JsonWriter(outputBuffer))
            {
                jsonWriter.WriteStartArray();

                using (JsonDocument jsonFcn = rizin.CommandJson("aflj"))
                {
                    if (jsonFcn == null)
                        return null;

                    foreach (var fcn in jsonFcn.RootElement.EnumerateArray())
                    {
                        decimal offset = fcn.GetProperty("offset").GetDecimal();
                        string name = fcn.GetProperty("name").GetString();
                        bool firstString = true;

                        using (JsonDocument jsonInst = rizin.CommandJson($"pifj @{offset}"))
                        {
                            if (jsonInst == null)
                                continue;
                            foreach (var inst in jsonInst.RootElement.GetProperty("ops").EnumerateArray())
                            {
                                JsonElement valElem, tmpElem;
                                if (!inst.TryGetProperty("val", out valElem))
                                    continue;
                                if (inst.TryGetProperty("refs", out tmpElem) && tmpElem.GetArrayLength() > 0)
                                    continue;
                                decimal opoffset = inst.GetProperty("offset").GetDecimal();
                                decimal size = inst.GetProperty("size").GetDecimal();
                                decimal val = valElem.GetDecimal();
                                string opcode = inst.GetProperty("opcode").GetString();
                                string type = inst.GetProperty("type").GetString();
                                if (type != "mov" && type != "push")
                                    continue;
                                byte[] data = BitConverter.GetBytes((ulong)val);
                                List<char> chars = new List<char>();
                                for (int i = 0; i < data.Length; i++)
                                {
                                    if (data[i] >= 0x20 && data[i] <= 0x7A)
                                    {
                                        char chr = (char)data[i];
                                        chars.Add(chr);
                                    }
                                }
                                if (chars.Count > 0)
                                {
                                    string str = new string(chars.ToArray());
                                    string strComm = new string(chars.ToArray());
                                    if (strComm.Contains('\\'))
                                    {
                                        strComm = strComm.Replace(backslash, doublebackslash);
                                    }
                                    if (strComm.Contains('\''))
                                    {
                                        strComm = strComm.Replace(mark, markescaped);
                                    }

                                    rizin.Command("fs+stackstrings");
                                    rizin.Command($"f loc.stackstring.{cnt} {size} @{opoffset}");
                                    rizin.Command($"fC loc.stackstring.{cnt} '{strComm}'");
                                    rizin.Command("fs-");
                                    cnt++;

                                    if (firstString)
                                    {
                                        jsonWriter.WriteStartObject();
                                        jsonWriter.WriteNumber("offset", offset);
                                        jsonWriter.WriteString("name", name);
                                        jsonWriter.WriteStartArray("ops");
                                        firstString = false;
                                    }
                                    jsonWriter.WriteStartObject();
                                    jsonWriter.WriteString("string", str);
                                    jsonWriter.WriteNumber("offset", opoffset);
                                    jsonWriter.WriteNumber("val", val);
                                    jsonWriter.WriteString("opcode", opcode);
                                    jsonWriter.WriteEndObject();
                                }
                            }
                        }
                        if (!firstString)
                        {
                            jsonWriter.WriteEndArray();
                            jsonWriter.WriteEndObject();
                        }
                    }
                }

                jsonWriter.WriteEndArray();
            }
            return JsonDocument.Parse(Encoding.UTF8.GetString(outputBuffer.WrittenSpan));
        }

        public void StackStrings()
        {
            using (JsonDocument json = GetStackStringsJson())
            {
                Generate(json, "stackstrings");
            }
        }
    }
}