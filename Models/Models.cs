using System;
using System.Collections.Generic;

namespace NetAudit.Models
{
    public enum ProtocolType
    {
        Tcp,
        Udp
    }

    public class ConnectionInfo
    {
        public int Pid;
        public string ProcessName;
        public ProtocolType Protocol;
        public string LocalAddress;
        public string RemoteAddress;
        public string State;
        public DateTime FirstSeen;
        public DateTime LastSeen;
        public bool IsOutbound;
        public string Key;

        public override string ToString()
        {
            return ProcessName + " [" + Pid + "] " + Protocol + " " + LocalAddress + " -> " + RemoteAddress;
        }
    }

    public class ProcessTraffic
    {
        public int Pid;
        public string Name;
        public long TxBytes;
        public long RxBytes;
        public double RateBytesPerSec;

        public double TxMB
        {
            get { return TxBytes / 1048576.0; }
        }

        public double RxMB
        {
            get { return RxBytes / 1048576.0; }
        }

        public double RateMBps
        {
            get { return RateBytesPerSec / 1048576.0; }
        }
    }

    public class AuditEvent
    {
        public DateTime Time;
        public string Level;
        public string Process;
        public int Pid;
        public string EventType;
        public string Detail;
    }

    public class AppSettings
    {
        public double HighRateMBps = 5.0;
        public string LogDirectory = "";
        public bool AlertSystemProcess = false;
        public bool AutoStart = true;
        public int RefreshIntervalMs = 1000;
    }
}
