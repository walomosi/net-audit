using System;
using System.IO;
using NetAudit.Models;

namespace NetAudit.Core
{
    /// <summary>
    /// Alerts tab: event CSV persisted to per-day files.
    /// </summary>
    internal class AuditLogger
    {
        private readonly object _sync = new object();
        private string _directory;

        public string DirectoryPath
        {
            get { return _directory; }
            set
            {
                _directory = value;
                if (!string.IsNullOrEmpty(_directory))
                {
                    try { Directory.CreateDirectory(_directory); }
                    catch { }
                }
            }
        }

        public AuditLogger(string directory)
        {
            DirectoryPath = directory;
        }

        public void Write(AuditEvent ev)
        {
            if (string.IsNullOrEmpty(_directory)) return;
            lock (_sync)
            {
                try
                {
                    string file = Path.Combine(_directory, "audit_" + DateTime.Now.ToString("yyyyMMdd") + ".csv");
                    string line = string.Format("{0},{1},{2},{3},{4},\"{5}\"",
                        ev.Time.ToString("yyyy-MM-dd HH:mm:ss"),
                        ev.Level,
                        ev.Process,
                        ev.Pid,
                        ev.EventType,
                        ev.Detail.Replace("\"", "\"\""));
                    File.AppendAllText(file, line + Environment.NewLine);
                }
                catch
                {
                }
            }
        }
    }
}
