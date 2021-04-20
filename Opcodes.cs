using System;
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
                    string name, perm;
                    decimal vaddr, vsize;
                    if (TryGetValue(dr, ".name", out name) &&
                        TryGetValue(dr, ".perm", out perm) &&
                        TryGetValue(dr, ".vaddr", out vaddr) &&
                        TryGetValue(dr, ".vsize", out vsize))
                    {
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
        }

        private static bool TryGetValue<T>(DataRow dr, string col, out T value)
        {
            if (dr[col] == DBNull.Value)
            {
                value = default(T);
                return false;
            }
            value = (T)dr[col];
            return true;
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