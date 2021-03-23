using System;
using System.Data;
using System.Runtime.InteropServices;
using System.Text.Json;
using toolbelt;

namespace rz_report
{
    public class Rizin : IDisposable
    {
        [DllImport("rz_core")]
        private static extern IntPtr rz_core_new();

        [DllImport("rz_core")]
        private static extern void rz_core_free(IntPtr core);

        [DllImport("rz_core")]
        private static extern void rz_core_cmd(IntPtr core, string cmd);

        [DllImport("rz_core")]
        private static extern string rz_core_cmd_str(IntPtr core, string cmd);

        [DllImport("rz_core")]
        private static extern IntPtr rz_core_get_config(IntPtr core);

        [DllImport("rz_core")]
        private static extern IntPtr rz_config_set(IntPtr config, string key, string value);

        [DllImport("rz_core")]
        private static extern IntPtr rz_config_set_i(IntPtr config, string key, long value);

        [DllImport("rz_core")]
        private static extern string rz_config_get(IntPtr config, string key);

        [DllImport("rz_core")]
        private static extern long rz_config_get_i(IntPtr config, string key);

        IntPtr core;

        public Rizin()
        {
            core = rz_core_new();
            SetConfig("scr.interactive", "true");
            SetConfig("io.cache", "true");
        }

        public void SetConfig(string key, string value)
        {
            IntPtr config = rz_core_get_config(core);
            rz_config_set(config, key, value);
        }

        public void SetConfig(string key, long value)
        {
            IntPtr config = rz_core_get_config(core);
            rz_config_set_i(config, key, value);
        }

        public string GetConfigString(string key)
        {
            IntPtr config = rz_core_get_config(core);
            return rz_config_get(config, key);
        }

        public long GetConfigInt64(string key)
        {
            IntPtr config = rz_core_get_config(core);
            return rz_config_get_i(config, key);
        }

        public void Command(string cmd)
        {
            rz_core_cmd(core, cmd);
        }

        public string CommandString(string cmd)
        {
            return rz_core_cmd_str(core, cmd);
        }

        public JsonDocument CommandJson(string cmd)
        {
            string data = CommandString(cmd);
            JsonDocument json;
            try
            {
                json = JsonDocument.Parse(data);
            }
            catch (JsonException)
            {
                return null;
            }
            return json;
        }

        public DataTable CommandDataTable(string cmd, string prefix = null)
        {
            using (JsonDocument json = CommandJson(cmd))
            {
                if (json == null)
                    return null;
                DataTable dt = new DataTable();
                dt.FromJson(json.RootElement, prefix);
                return dt;
            }
        }

        public void CommandAnalyzeBinary()
        {
            // Analyze all
            Command("aaa");

            // Add signatures for special binary markers and search them
            Command("za prelude.intel.a b 8bff558bec:ffffffffff");
            Command("za prelude.intel.b b 558bec:ffffff");
            Command("za prelude.gcc b 5589e5:ffffff");
            Command("za mark.cpp.thispointer b 568bf1:ffffff");
            Command("za mark.seh.setupentry b 6a006800000000e8:ff00ff00000000ff");
            Command("z/");

            // Run analyze function on all prelude matches
            Command("af @@f:sign.bytes.prelude.*");
        }

        private void DisposeInternal()
        {
            rz_core_free(core);
            core = IntPtr.Zero;
        }

        ~Rizin()
        {
            DisposeInternal();
        }

        public void Dispose()
        {
            DisposeInternal();
        }
    }
}