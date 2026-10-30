using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace NetAudit.Core
{
    /// <summary>
    /// Per-process traffic collection.
    /// Primary: TraceEvent real-time kernel session (Kernel Network TCPIP provider, TCP/UDP/IP events),
    /// kernel buffers deliver in batches - far lower CPU than an EventLogWatcher on the Analytic channel.
    /// On failure, fall back to Process\IO Data Bytes/sec (incl. disk IO, approximate only).
    /// </summary>
    internal class TrafficMonitor
    {
        private readonly object _sync = new object();
        private readonly Dictionary<int, long> _tx = new Dictionary<int, long>();
        private readonly Dictionary<int, long> _rx = new Dictionary<int, long>();
        private readonly Dictionary<int, string> _udpTarget = new Dictionary<int, string>();
        private readonly ProcessResolver _resolver;

        private TraceEventSession _session;
        private ETWTraceEventSource _source;
        private Thread _thread;
        private volatile bool _running;
        private bool _usingEtw;

        public TrafficMonitor(ProcessResolver resolver)
        {
            _resolver = resolver;
        }

        public bool UsingEtw
        {
            get { return _usingEtw; }
        }

        public void Start()
        {
            if (_running) return;
            _running = true;
            try
            {
                // session name carries a PID suffix to avoid collisions with stale instances holding the same kernel session
                string sessionName = "NetAuditKernelSession_" + System.Diagnostics.Process.GetCurrentProcess().Id;
                _session = new TraceEventSession(sessionName, TraceEventSessionOptions.Create);
                _session.StopOnDispose = true;
                _session.BufferSizeMB = 16;
                _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

                _source = new ETWTraceEventSource(sessionName, TraceEventSourceType.Session);
                _source.Kernel.TcpIpSend += OnTcpIpSend;
                _source.Kernel.TcpIpRecv += OnTcpIpReceive;
                _source.Kernel.UdpIpSend += OnUdpIpSend;
                _source.Kernel.UdpIpRecv += OnUdpIpReceive;

                _thread = new Thread(RunSource);
                _thread.IsBackground = true;
                _thread.Name = "NetAuditEtw";
                _thread.Start();
                _usingEtw = true;
            }
            catch
            {
                _usingEtw = false;
                try { if (_session != null) _session.Dispose(); }
                catch { }
                _session = null;
            }
        }

        public void Stop()
        {
            _running = false;
            try
            {
                if (_session != null)
                {
                    _session.Dispose();
                    _session = null;
                }
            }
            catch
            {
            }
            try
            {
                if (_source != null)
                {
                    _source.Dispose();
                    _source = null;
                }
            }
            catch
            {
            }
            try
            {
                if (_thread != null) _thread.Join(1000);
            }
            catch
            {
            }
            _thread = null;
        }

        private void RunSource()
        {
            try
            {
                if (_source != null) _source.Process();
            }
            catch
            {
            }
        }

        private void OnTcpIpSend(Microsoft.Diagnostics.Tracing.Parsers.Kernel.TcpIpSendTraceData data)
        {
            AddTraffic(data.ProcessID, Convert.ToInt64(data.size), true);
        }

        private void OnTcpIpReceive(Microsoft.Diagnostics.Tracing.Parsers.Kernel.TcpIpTraceData data)
        {
            AddTraffic(data.ProcessID, Convert.ToInt64(data.size), false);
        }

        private void OnUdpIpSend(Microsoft.Diagnostics.Tracing.Parsers.Kernel.UdpIpTraceData data)
        {
            AddTraffic(data.ProcessID, Convert.ToInt64(data.size), true);
            RecordUdpTarget(data.ProcessID, data.daddr, data.dport);
        }

        private void OnUdpIpReceive(Microsoft.Diagnostics.Tracing.Parsers.Kernel.UdpIpTraceData data)
        {
            AddTraffic(data.ProcessID, Convert.ToInt64(data.size), false);
            RecordUdpTarget(data.ProcessID, data.daddr, data.dport);
        }

        private void AddTraffic(int pid, long size, bool isSend)
        {
            if (pid <= 0 || size < 0) return;
            lock (_sync)
            {
                if (isSend)
                {
                    long v;
                    _tx.TryGetValue(pid, out v);
                    _tx[pid] = v + size;
                }
                else
                {
                    long v;
                    _rx.TryGetValue(pid, out v);
                    _rx[pid] = v + size;
                }
            }
        }

        private void RecordUdpTarget(int pid, IPAddress daddr, int dport)
        {
            if (pid <= 0 || daddr == null) return;
            string tgt;
            try
            {
                tgt = daddr.ToString() + ":" + dport;
            }
            catch
            {
                return;
            }
            lock (_sync)
            {
                _udpTarget[pid] = tgt;
            }
        }

        public string GetUdpTarget(int pid)
        {
            lock (_sync)
            {
                string t;
                return _udpTarget.TryGetValue(pid, out t) ? t : "";
            }
        }

        /// <summary>Snapshot all UDP targets at once (avoids per-row UI locking).</summary>
        public Dictionary<int, string> GetUdpTargetsSnapshot()
        {
            lock (_sync)
            {
                return new Dictionary<int, string>(_udpTarget);
            }
        }

        public void GetTotals(out Dictionary<int, long> tx, out Dictionary<int, long> rx)
        {
            lock (_sync)
            {
                tx = new Dictionary<int, long>(_tx);
                rx = new Dictionary<int, long>(_rx);
            }
        }

        /// <summary>
        /// Degraded mode: read IO Data Bytes/sec per process (incl. disk IO, approximate).
        /// </summary>
        public Dictionary<int, double> EstimateIoSnapshot()
        {
            Dictionary<int, double> result = new Dictionary<int, double>();
            try
            {
                PerformanceCounterCategory cat = new PerformanceCounterCategory("Process");
                string[] instances = cat.GetInstanceNames();
                foreach (string inst in instances)
                {
                    try
                    {
                        using (PerformanceCounter pcPid = new PerformanceCounter("Process", "ID Process", inst, true))
                        using (PerformanceCounter pcIo = new PerformanceCounter("Process", "IO Data Bytes/sec", inst, true))
                        {
                            int pid = (int)pcPid.NextValue();
                            double v1 = pcIo.NextValue();
                            double v2 = pcIo.NextValue();
                            // take the larger of two samples as the rate; no Sleep, to avoid blocking the UI thread
                            if (pid > 0) result[pid] = v1 > v2 ? v1 : v2;
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return result;
        }
    }
}
