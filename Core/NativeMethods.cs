using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using NetAudit.Models;

namespace NetAudit.Core
{
    /// <summary>
    /// Poll the TCP/UDP table (IPv4 + IPv6) via iphlpapi for per-process connection info.
    /// </summary>
    internal static class NativeMethods
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int TableClass, uint Reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, int TableClass, uint Reserved);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public uint owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPROW_OWNER_PID
        {
            public uint localAddr;
            public uint localPort;
            public uint owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] localAddr;
            public uint localScopeId;
            public uint localPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] remoteAddr;
            public uint remoteScopeId;
            public uint remotePort;
            public uint state;
            public uint owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] localAddr;
            public uint localScopeId;
            public uint localPort;
            public uint owningPid;
        }

        private const int AF_INET = 2;
        private const int AF_INET6 = 23;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const int UDP_TABLE_OWNER_PID = 1;
        private const uint NO_ERROR = 0;
        private const int ROW_TCP = 24;  // MIB_TCPROW_OWNER_PID: 6 * uint
        private const int ROW_UDP = 12;  // MIB_UDPROW_OWNER_PID: 3 * uint
        private const int ROW_TCP6 = 56; // 16+4+4+16+4+4+4+4
        private const int ROW_UDP6 = 28; // 16+4+4+4

        private static string FormatPort(uint p)
        {
            int port = IPAddress.NetworkToHostOrder((short)(p & 0xFFFF));
            return (port & 0xFFFF).ToString();
        }

        private static IPAddress AddrFromUint(uint a)
        {
            return new IPAddress(BitConverter.GetBytes(a));
        }

        private static string StateName(uint s)
        {
            switch (s)
            {
                case 1: return "CLOSED";
                case 2: return "LISTEN";
                case 3: return "SYN_SENT";
                case 4: return "SYN_RCVD";
                case 5: return "ESTABLISHED";
                case 6: return "FIN_WAIT1";
                case 7: return "FIN_WAIT2";
                case 8: return "CLOSE_WAIT";
                case 9: return "CLOSING";
                case 10: return "LAST_ACK";
                case 11: return "TIME_WAIT";
                case 12: return "DELETE_TCB";
                default: return "UNKNOWN";
            }
        }

        /// <summary>Whether an IPv4 address is public (outbound).</summary>
        public static bool IsPublicRemote(uint remoteAddr)
        {
            if (remoteAddr == 0) return false;
            byte[] b = BitConverter.GetBytes(remoteAddr);
            byte a = b[0];
            if (a == 0) return false;
            if (a == 10) return false;                 // 10.0.0.0/8
            if (a == 127) return false;                // loopback
            if (a == 169 && b[1] == 254) return false; // link-local
            if (a == 172 && b[1] >= 16 && b[1] <= 31) return false; // 172.16/12
            if (a == 192 && b[1] == 168) return false; // 192.168/16
            return true;
        }

        /// <summary>Whether an IPv6 address is public (global unicast).</summary>
        public static bool IsPublicRemote6(byte[] addr)
        {
            if (addr == null || addr.Length != 16) return false;
            bool allZero = true;
            for (int i = 0; i < 16; i++)
            {
                if (addr[i] != 0)
                {
                    allZero = false;
                    break;
                }
            }
            if (allZero) return false;                      // ::
            bool loopback = true;
            for (int i = 0; i < 15; i++)
            {
                if (addr[i] != 0)
                {
                    loopback = false;
                    break;
                }
            }
            if (loopback && addr[15] == 1) return false;    // ::1
            if ((addr[0] & 0xFE) == 0xFC) return false;     // fc00::/7 ULA private
            if (addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80) return false; // fe80::/10 link-local
            return true;
        }

        public static List<ConnectionInfo> GetTcpConnections()
        {
            List<ConnectionInfo> list = GetTcpConnectionsV4();
            list.AddRange(GetTcpConnectionsV6());
            return list;
        }

        public static List<ConnectionInfo> GetUdpConnections()
        {
            List<ConnectionInfo> list = GetUdpConnectionsV4();
            list.AddRange(GetUdpConnectionsV6());
            return list;
        }

        private static List<ConnectionInfo> GetTcpConnectionsV4()
        {
            List<ConnectionInfo> list = new List<ConnectionInfo>();
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size <= 0) return list;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                uint r = GetExtendedTcpTable(buf, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (r == NO_ERROR && size >= 4)
                {
                    uint count = (uint)Marshal.ReadInt32(buf);
                    IntPtr p = IntPtr.Add(buf, 4);
                    for (uint i = 0; i < count; i++)
                    {
                        if (p.ToInt64() + ROW_TCP > buf.ToInt64() + size) break;
                        MIB_TCPROW_OWNER_PID row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(p, typeof(MIB_TCPROW_OWNER_PID));
                        ConnectionInfo c = new ConnectionInfo();
                        c.Protocol = ProtocolType.Tcp;
                        c.Pid = (int)row.owningPid;
                        c.LocalAddress = AddrFromUint(row.localAddr).ToString() + ":" + FormatPort(row.localPort);
                        c.RemoteAddress = AddrFromUint(row.remoteAddr).ToString() + ":" + FormatPort(row.remotePort);
                        c.State = StateName(row.state);
                        c.FirstSeen = DateTime.Now;
                        c.LastSeen = DateTime.Now;
                        c.IsOutbound = IsPublicRemote(row.remoteAddr);
                        c.Key = "T:" + row.owningPid + ":" + c.LocalAddress + ":" + c.RemoteAddress;
                        list.Add(c);
                        p = IntPtr.Add(p, ROW_TCP);
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
            return list;
        }

        private static List<ConnectionInfo> GetTcpConnectionsV6()
        {
            List<ConnectionInfo> list = new List<ConnectionInfo>();
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size <= 0) return list;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                uint r = GetExtendedTcpTable(buf, ref size, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
                if (r == NO_ERROR && size >= 4)
                {
                    uint count = (uint)Marshal.ReadInt32(buf);
                    IntPtr p = IntPtr.Add(buf, 4);
                    for (uint i = 0; i < count; i++)
                    {
                        if (p.ToInt64() + ROW_TCP6 > buf.ToInt64() + size) break;
                        MIB_TCP6ROW_OWNER_PID row = (MIB_TCP6ROW_OWNER_PID)Marshal.PtrToStructure(p, typeof(MIB_TCP6ROW_OWNER_PID));
                        ConnectionInfo c = new ConnectionInfo();
                        c.Protocol = ProtocolType.Tcp;
                        c.Pid = (int)row.owningPid;
                        c.LocalAddress = new IPAddress(row.localAddr).ToString() + ":" + FormatPort(row.localPort);
                        c.RemoteAddress = new IPAddress(row.remoteAddr).ToString() + ":" + FormatPort(row.remotePort);
                        c.State = StateName(row.state);
                        c.FirstSeen = DateTime.Now;
                        c.LastSeen = DateTime.Now;
                        c.IsOutbound = IsPublicRemote6(row.remoteAddr);
                        c.Key = "T6:" + row.owningPid + ":" + c.LocalAddress + ":" + c.RemoteAddress;
                        list.Add(c);
                        p = IntPtr.Add(p, ROW_TCP6);
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
            return list;
        }

        private static List<ConnectionInfo> GetUdpConnectionsV4()
        {
            List<ConnectionInfo> list = new List<ConnectionInfo>();
            int size = 0;
            GetExtendedUdpTable(IntPtr.Zero, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (size <= 0) return list;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                uint r = GetExtendedUdpTable(buf, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0);
                if (r == NO_ERROR && size >= 4)
                {
                    uint count = (uint)Marshal.ReadInt32(buf);
                    IntPtr p = IntPtr.Add(buf, 4);
                    for (uint i = 0; i < count; i++)
                    {
                        if (p.ToInt64() + ROW_UDP > buf.ToInt64() + size) break;
                        MIB_UDPROW_OWNER_PID row = (MIB_UDPROW_OWNER_PID)Marshal.PtrToStructure(p, typeof(MIB_UDPROW_OWNER_PID));
                        ConnectionInfo c = new ConnectionInfo();
                        c.Protocol = ProtocolType.Udp;
                        c.Pid = (int)row.owningPid;
                        c.LocalAddress = AddrFromUint(row.localAddr).ToString() + ":" + FormatPort(row.localPort);
                        c.RemoteAddress = "0.0.0.0:0";
                        c.State = "";
                        c.FirstSeen = DateTime.Now;
                        c.LastSeen = DateTime.Now;
                        c.IsOutbound = false;
                        c.Key = "U:" + row.owningPid + ":" + c.LocalAddress;
                        list.Add(c);
                        p = IntPtr.Add(p, ROW_UDP);
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
            return list;
        }

        private static List<ConnectionInfo> GetUdpConnectionsV6()
        {
            List<ConnectionInfo> list = new List<ConnectionInfo>();
            int size = 0;
            GetExtendedUdpTable(IntPtr.Zero, ref size, false, AF_INET6, UDP_TABLE_OWNER_PID, 0);
            if (size <= 0) return list;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                uint r = GetExtendedUdpTable(buf, ref size, false, AF_INET6, UDP_TABLE_OWNER_PID, 0);
                if (r == NO_ERROR && size >= 4)
                {
                    uint count = (uint)Marshal.ReadInt32(buf);
                    IntPtr p = IntPtr.Add(buf, 4);
                    for (uint i = 0; i < count; i++)
                    {
                        if (p.ToInt64() + ROW_UDP6 > buf.ToInt64() + size) break;
                        MIB_UDP6ROW_OWNER_PID row = (MIB_UDP6ROW_OWNER_PID)Marshal.PtrToStructure(p, typeof(MIB_UDP6ROW_OWNER_PID));
                        ConnectionInfo c = new ConnectionInfo();
                        c.Protocol = ProtocolType.Udp;
                        c.Pid = (int)row.owningPid;
                        c.LocalAddress = new IPAddress(row.localAddr).ToString() + ":" + FormatPort(row.localPort);
                        c.RemoteAddress = "::";
                        c.State = "";
                        c.FirstSeen = DateTime.Now;
                        c.LastSeen = DateTime.Now;
                        c.IsOutbound = false;
                        c.Key = "U6:" + row.owningPid + ":" + c.LocalAddress;
                        list.Add(c);
                        p = IntPtr.Add(p, ROW_UDP6);
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
            return list;
        }
    }
}
