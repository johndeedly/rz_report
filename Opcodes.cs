using System.Data;
using System.IO;
using System.Linq;
using System.Text;

namespace rz_report
{
    public class Opcodes
    {
        Rizin rizin;
        string path;

        public Opcodes(Rizin rizin, string path)
        {
            this.rizin = rizin;
            this.path = $"{path}/opcodes";
            Directory.CreateDirectory(this.path);
        }

        public void Disassemble()
        {
            using (DataTable dt = rizin.CommandDataTable("iSj"))
            {
                int i = 0;
                foreach (var dr in dt.Rows.OfType<DataRow>().Where(x => ((string)x[".perm"]).Contains("x")))
                {
                    string name = (string)dr[".name"];
                    string perm = (string)dr[".perm"];
                    decimal vaddr = (decimal)dr[".vaddr"];
                    decimal vsize = (decimal)dr[".vsize"];
                    
                    using (var stream = new FileStream($"{path}/{i++}_{perm}_{name}.txt", FileMode.Create, FileAccess.Write, FileShare.Read))
                    {
                        stream.Write(Encoding.UTF8.GetBytes($"[{name}]\n"));
                        DisassembleSection(vaddr, vsize, stream);
                        stream.WriteByte(10);
                        stream.Flush();
                    }
                }
            }
        }

        private void DisassembleSection(decimal vaddr, decimal vsize, Stream stream)
        {
            string colors = rizin.CommandString("e scr.color");
            string lines = rizin.CommandString("e asm.lines");
            rizin.Command("e scr.color=0");
            rizin.Command("e asm.lines=false");
            string opcodes = rizin.CommandString($"pD {vsize} @{vaddr}");
            rizin.Command($"e scr.color={colors}");
            rizin.Command($"e asm.lines={lines}");
            byte[] data = Encoding.UTF8.GetBytes(opcodes);
            stream.Write(data, 0, data.Length);
        }
    }
}