using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace NetAudit.Core
{
    /// <summary>
    /// Resolve PID -> process name, with a cache (processes exit fast, cache aggressively).
    /// </summary>
    internal class ProcessResolver
    {
        private readonly Dictionary<int, string> _names = new Dictionary<int, string>();
        private readonly Dictionary<int, string> _paths = new Dictionary<int, string>();
        private readonly object _sync = new object();

        public string GetName(int pid)
        {
            lock (_sync)
            {
                string n;
                if (_names.TryGetValue(pid, out n)) return n;
                n = ResolveName(pid);
                _names[pid] = n;
                return n;
            }
        }

        public string GetPath(int pid)
        {
            lock (_sync)
            {
                string p;
                if (_paths.TryGetValue(pid, out p)) return p;
                p = ResolvePath(pid);
                _paths[pid] = p;
                return p;
            }
        }

        public void Invalidate(int pid)
        {
            lock (_sync)
            {
                _names.Remove(pid);
                _paths.Remove(pid);
            }
        }

        private static string ResolveName(int pid)
        {
            try
            {
                using (Process p = Process.GetProcessById(pid))
                {
                    return p.ProcessName;
                }
            }
            catch
            {
                return "PID " + pid + " (exited)";
            }
        }

        private static string ResolvePath(int pid)
        {
            try
            {
                using (Process p = Process.GetProcessById(pid))
                {
                    if (p == null) return "";
                    try { return p.MainModule.FileName; }
                    catch { return ""; }
                }
            }
            catch
            {
                return "";
            }
        }
    }
}
