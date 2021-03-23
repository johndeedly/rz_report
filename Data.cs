using System.Data;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace rz_report
{
    public class Data
    {
        Rizin rizin;
        string path;

        public Data(Rizin rizin, string path)
        {
            this.rizin = rizin;
            this.path = $"{path}/data";
            Directory.CreateDirectory(this.path);
        }

        public void Export()
        {
            Sections();
            Resources();
        }

        private void Sections()
        {
            decimal fileSize = GetMainFileSize();
            MapMainFileToOffsetZero();
            using (DataTable dt = rizin.CommandDataTable("iSj"))
            {
                if (dt == null || dt.Rows.Count == 0)
                    return;

                int index = 0;
                foreach (DataRow dr in dt.Rows)
                {
                    string name = (string)dr[".name"];
                    decimal paddr = (decimal)dr[".paddr"];
                    decimal size = (decimal)dr[".size"];

                    using (var stream = new FileStream($"{path}/sec_{index++}_{name}.bin", FileMode.Create, FileAccess.Write, FileShare.Read))
                    {
                        DumpRangeToFile(paddr, size, stream);
                        stream.Flush();
                    }
                }

                decimal overlayOffset = GetOverlayOffset(dt);
                if (overlayOffset < fileSize)
                {
                    using (var stream = new FileStream($"{path}/sec_{index++}_overlay.bin", FileMode.Create, FileAccess.Write, FileShare.Read))
                    {
                        DumpRangeToFile(overlayOffset, fileSize - overlayOffset, stream);
                        stream.Flush();
                    }
                }
            }
            UnloadMappedFileAtOffsetZero();
        }

        private decimal GetMainFileSize()
        {
            using (DataTable dt = rizin.CommandDataTable("ij"))
            {
                decimal fileSize = (decimal)dt.Rows[0][".core.size"];
                return fileSize;
            }
        }

        private static decimal GetOverlayOffset(DataTable dt)
        {
            DataRow lastSection = dt.Rows.OfType<DataRow>().OrderBy(x => (decimal)x[".paddr"]).Last();
            decimal lastAddr = (decimal)lastSection[".paddr"];
            decimal lastSize = (decimal)lastSection[".size"];
            decimal overlayOffset = lastAddr + lastSize;
            return overlayOffset;
        }

        private void UnloadMappedFileAtOffsetZero()
        {
            using (DataTable dt = rizin.CommandDataTable("oj"))
            {
                DataRow last = dt.Rows.OfType<DataRow>().OrderBy(x => (decimal)x[".fd"]).Last();
                decimal fd = (decimal)last[".fd"];
                rizin.Command($"o-{fd}");
            }
        }

        private void MapMainFileToOffsetZero()
        {
            string mainFilePath = rizin.CommandString("o.").TrimEnd();
            rizin.Command($"on \"{mainFilePath}\" 0x0");
        }

        private void Resources()
        {
            using (DataTable dt = rizin.CommandDataTable("iRj"))
            {
                if (dt == null)
                    return;

                foreach (DataRow dr in dt.Rows)
                {
                    string name = (string)dr[".name"];
                    decimal index = (decimal)dr[".index"];
                    decimal vaddr = (decimal)dr[".vaddr"];
                    decimal size = (decimal)dr[".size"];

                    using (var stream = new FileStream($"{path}/res_{index}_{name}.bin", FileMode.Create, FileAccess.Write, FileShare.Read))
                    {
                        DumpRangeToFile(vaddr, size, stream);
                        stream.Flush();
                    }
                }
            }
        }

        private void DumpRangeToFile(decimal vaddr, decimal size, Stream stream)
        {
            using (JsonDocument json = rizin.CommandJson($"pxj {size} @{vaddr}"))
            {
                int length = json.RootElement.GetArrayLength();
                byte[] data = new byte[length];
                int i = 0;
                foreach (var elem in json.RootElement.EnumerateArray())
                {
                    data[i++] = elem.GetByte();
                }
                stream.Write(data, 0, length);
            }
        }
    }
}