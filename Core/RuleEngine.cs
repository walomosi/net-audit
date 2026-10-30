using System;
using System.Collections.Generic;
using NetAudit.Models;

namespace NetAudit.Core
{
    /// <summary>
    /// Detection rules:
    /// 1. New outbound connection (public destination)
    /// 2. Unusual remote port
    /// 3. Local listener on a low port
    /// 4. High-traffic process
    /// 5. Record UDP-speaking processes
    /// </summary>
    internal class RuleEngine
    {
        public event Action<AuditEvent> OnEvent;

        private readonly AppSettings _settings;
        private readonly HashSet<string> _notified = new HashSet<string>();
        private readonly HashSet<int> _wellKnownPorts = new HashSet<int>();
        private readonly object _sync = new object();

        public RuleEngine(AppSettings settings)
        {
            _settings = settings;
            foreach (int p in new int[]
            {
                20, 21, 22, 25, 53, 80, 110, 123, 143, 161, 389, 443, 445, 465, 587, 636,
                993, 995, 1080, 1433, 1521, 3306, 3389, 5222, 5228, 5229, 5230, 5432, 5900,
                6379, 6667, 6697, 8000, 8080, 8443, 8888, 9000, 9090, 9418, 1935, 3478, 3479,
                5060, 5061, 27015, 27017, 27036, 3074, 3724, 6112, 11235, 25565
            })
            {
                _wellKnownPorts.Add(p);
            }
        }

        public void CheckNewConnection(ConnectionInfo c)
        {
            if (_settings.AlertSystemProcess && IsSystemProcess(c.ProcessName)) return;
            if (c.ProcessName == null) return;

            if (c.Protocol == ProtocolType.Tcp && c.IsOutbound)
            {
                string key = "out:" + c.Pid + ":" + c.RemoteAddress;
                lock (_sync)
                {
                    if (_notified.Add(key))
                    {
                        Emit("Info", c.ProcessName, c.Pid, "New outbound",
                            c.ProcessName + " opened public connection " + c.LocalAddress + " -> " + c.RemoteAddress);
                    }
                }

                int rport = ExtractPort(c.RemoteAddress);
                if (rport > 0 && !_wellKnownPorts.Contains(rport))
                {
                    string k2 = "port:" + c.Pid + ":" + c.RemoteAddress;
                    lock (_sync)
                    {
                        if (_notified.Add(k2))
                        {
                            Emit("Warn", c.ProcessName, c.Pid, "Unusual port",
                                c.ProcessName + " connected to unusual port " + c.RemoteAddress + " (uncommon service port, please review)");
                        }
                    }
                }
            }

            if (c.Protocol == ProtocolType.Tcp && c.State == "LISTEN")
            {
                int lport = ExtractPort(c.LocalAddress);
                if (lport > 0 && lport < 1024 && !_wellKnownPorts.Contains(lport))
                {
                    string k3 = "listen:" + c.Pid + ":" + c.LocalAddress;
                    lock (_sync)
                    {
                        if (_notified.Add(k3))
                        {
                            Emit("Info", c.ProcessName, c.Pid, "Local listener",
                                c.ProcessName + " is listening on low port " + c.LocalAddress + " (review if not an expected service)");
                        }
                    }
                }
            }
        }

        public void CheckHighTraffic(List<ProcessTraffic> list)
        {
            double threshold = _settings.HighRateMBps * 1048576.0;
            foreach (ProcessTraffic t in list)
            {
                if (t.RateBytesPerSec > threshold)
                {
                    string key = "rate:" + t.Pid;
                    bool need;
                    lock (_sync)
                    {
                        need = _notified.Add(key);
                    }
                    if (need)
                    {
                        Emit("Alert", t.Name, t.Pid, "High traffic",
                            t.Name + " current rate " + t.RateMBps.ToString("0.0") + " MB/s, above threshold " +
                            _settings.HighRateMBps.ToString("0.0") + " MB/s");
                    }
                }
            }
        }

        public void ClearNotified()
        {
            lock (_sync)
            {
                _notified.Clear();
            }
        }

        private static bool IsSystemProcess(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            switch (name.ToLower())
            {
                case "system":
                case "system idle process":
                case "svchost":
                case "lsass":
                case "csrss":
                case "services":
                case "wininit":
                case "winlogon":
                case "explorer":
                    return true;
                default:
                    return false;
            }
        }

        private static int ExtractPort(string addr)
        {
            if (string.IsNullOrEmpty(addr)) return 0;
            int idx = addr.LastIndexOf(':');
            if (idx < 0) return 0;
            int p;
            if (int.TryParse(addr.Substring(idx + 1), out p)) return p;
            return 0;
        }

        private void Emit(string level, string process, int pid, string type, string detail)
        {
            AuditEvent ev = new AuditEvent();
            ev.Time = DateTime.Now;
            ev.Level = level;
            ev.Process = process;
            ev.Pid = pid;
            ev.EventType = type;
            ev.Detail = detail;
            Action<AuditEvent> h = OnEvent;
            if (h != null) h(ev);
        }
    }
}
