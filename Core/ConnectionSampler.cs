using System;
using System.Collections.Generic;
using NetAudit.Models;

namespace NetAudit.Core
{
    /// <summary>
    /// Connections tab: poll the TCP/UDP table, maintain the current connection set, detect new connections.
    /// </summary>
    internal class ConnectionSampler
    {
        public event Action<ConnectionInfo> NewConnection;

        private readonly Dictionary<string, ConnectionInfo> _current = new Dictionary<string, ConnectionInfo>();
        private readonly object _sync = new object();
        private readonly ProcessResolver _resolver;

        public ConnectionSampler(ProcessResolver resolver)
        {
            _resolver = resolver;
        }

        public void Sample()
        {
            List<ConnectionInfo> rows = NativeMethods.GetTcpConnections();
            rows.AddRange(NativeMethods.GetUdpConnections());
            foreach (ConnectionInfo r in rows)
            {
                r.ProcessName = _resolver.GetName(r.Pid);
            }

            lock (_sync)
            {
                HashSet<string> seen = new HashSet<string>();
                foreach (ConnectionInfo r in rows)
                {
                    if (seen.Contains(r.Key)) continue;
                    seen.Add(r.Key);
                    ConnectionInfo old;
                    if (_current.TryGetValue(r.Key, out old))
                    {
                        old.LastSeen = DateTime.Now;
                        old.State = r.State;
                    }
                    else
                    {
                        _current[r.Key] = r;
                        Action<ConnectionInfo> h = NewConnection;
                        if (h != null) h(r);
                    }
                }

                List<string> gone = new List<string>();
                foreach (KeyValuePair<string, ConnectionInfo> kv in _current)
                {
                    if (!seen.Contains(kv.Key)) gone.Add(kv.Key);
                }
                foreach (string k in gone)
                {
                    _current.Remove(k);
                }
            }
        }

        public List<ConnectionInfo> GetCurrent()
        {
            lock (_sync)
            {
                List<ConnectionInfo> copy = new List<ConnectionInfo>();
                foreach (ConnectionInfo c in _current.Values)
                {
                    copy.Add(c);
                }
                return copy;
            }
        }

        public void Clear()
        {
            lock (_sync)
            {
                _current.Clear();
            }
        }
    }
}
