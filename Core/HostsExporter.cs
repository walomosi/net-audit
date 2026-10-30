using System;
using System.Collections.Generic;
using System.Text;
using NetAudit.Models;

namespace NetAudit.Core
{
    /// <summary>
    /// Export a "suspicious connections" list to feed accelerator / hosts / firewall rules.
    /// Note: hosts only blocks domains; for IPs use firewall rules or your accelerator block/route logic.
    /// </summary>
    internal static class HostsExporter
    {
        /// <summary>
        /// Collect public-destination IPs from alert events + current connections, build the blacklist text.
        /// </summary>
        public static string BuildIpBlacklist(List<AuditEvent> events, List<ConnectionInfo> conns)
        {
            Dictionary<string, string> ipProc = new Dictionary<string, string>();
            Dictionary<string, DateTime> ipFirst = new Dictionary<string, DateTime>();

            foreach (AuditEvent ev in events)
            {
                string ip = ExtractIpFromDetail(ev.Detail);
                if (ip != null && !ipProc.ContainsKey(ip))
                {
                    ipProc[ip] = ev.Process;
                    ipFirst[ip] = ev.Time;
                }
            }
            foreach (ConnectionInfo c in conns)
            {
                if (c.IsOutbound && c.RemoteAddress != null)
                {
                    string ip = ExtractIp(c.RemoteAddress);
                    if (ip != null && !ipProc.ContainsKey(ip))
                    {
                        ipProc[ip] = c.ProcessName;
                        ipFirst[ip] = c.FirstSeen;
                    }
                }
            }

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("# NetAudit suspicious public-destination IP list");
            sb.AppendLine("# Generated: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("# Use: reference for accelerator/firewall block or route rules. hosts only blocks domains; use firewall rules for IPs.");
            sb.AppendLine("# Format: target IP | first seen | related process");
            sb.AppendLine();
            List<string> ips = new List<string>(ipProc.Keys);
            ips.Sort();
            foreach (string ip in ips)
            {
                sb.AppendLine(ip + " | " + ipFirst[ip].ToString("yyyy-MM-dd HH:mm:ss") + " | " + ipProc[ip]);
            }
            return sb.ToString();
        }

        /// <summary>
        /// Build a hosts template (with notes and example firewall commands).
        /// </summary>
        public static string BuildHostsTemplate(List<AuditEvent> events, List<ConnectionInfo> conns)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("# NetAudit hosts block template");
            sb.AppendLine("# Note: hosts only blocks domains. Append domains to block in this format to C:\\Windows\\System32\\drivers\\etc\\hosts");
            sb.AppendLine("# 0.0.0.0 example.com");
            sb.AppendLine("#");
            sb.AppendLine("# For suspicious IPs, block via firewall. Example (admin):");
            sb.AppendLine("# netsh advfirewall firewall add rule name=\"NetAuditBlock1\" dir=out remoteip=1.2.3.4 action=block");
            sb.AppendLine("#");
            sb.AppendLine("# Recently audited suspicious public IPs (deduplicated):");
            Dictionary<string, string> ips = new Dictionary<string, string>();
            foreach (AuditEvent ev in events)
            {
                string ip = ExtractIpFromDetail(ev.Detail);
                if (ip != null && !ips.ContainsKey(ip)) ips[ip] = ev.Process;
            }
            foreach (ConnectionInfo c in conns)
            {
                if (c.IsOutbound && c.RemoteAddress != null)
                {
                    string ip = ExtractIp(c.RemoteAddress);
                    if (ip != null && !ips.ContainsKey(ip)) ips[ip] = c.ProcessName;
                }
            }
            foreach (KeyValuePair<string, string> kv in ips)
            {
                sb.AppendLine("# " + kv.Key + "   (process: " + kv.Value + ")");
            }
            return sb.ToString();
        }

        private static string ExtractIp(string addr)
        {
            if (string.IsNullOrEmpty(addr)) return null;
            int idx = addr.LastIndexOf(':');
            if (idx <= 0) return null;
            return addr.Substring(0, idx);
        }

        private static string ExtractIpFromDetail(string detail)
        {
            if (string.IsNullOrEmpty(detail)) return null;
            int idx = detail.IndexOf(" -> ");
            if (idx < 0) return null;
            string target = detail.Substring(idx + 4);
            int p = target.IndexOf(':');
            if (p < 0) return null;
            string ip = target.Substring(0, p);
            if (string.IsNullOrEmpty(ip)) return null;
            return ip;
        }
    }
}
