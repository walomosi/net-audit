# NetAudit

**Stop guessing what your Windows box is talking to.** NetAudit answers three questions, per process, in real time: *who* is phoning home, *who* it's talking to, and *how much* data is moving.

No kernel driver, no service install, no telemetry of its own. One WinForms executable, ETW kernel events under the hood, .NET Framework 4.8.

---

## Why

Task Manager shows you a total network graph. It doesn't tell you:

- which process just opened an outbound connection to a brand-new IP
- what UDP targets a background process keeps hammering
- which process is listening on an unusual low port
- how many bytes each process has actually sent and received since boot

NetAudit shows you all of that, in four tabs, with alerts for the interesting stuff.

## Features

| | |
|---|---|
| **Per-process traffic** | Real upload/download counters from ETW kernel network events — not the rounded "IO" estimate in Task Manager. |
| **Connection audit** | Polls the TCP/UDP table every second: process, local/remote address, state, first-seen / last-seen, outbound vs. internal. IPv4 + IPv6. |
| **Smart alerts** | Flags new outbound connections, unusual remote ports, local listeners on low ports, and processes crossing a configurable traffic threshold. Levels: Info / Warn / Alert. |
| **Degraded fallback** | Without admin rights it falls back to process IO counters (labeled "estimated" in the UI) — still useful, just approximate. |
| **One-click exports** | Deduplicated suspicious public-IP list, plus a hosts template with ready-to-paste `netsh advfirewall` commands for blocking those IPs. |
| **Per-day CSV logs** | Every alert is appended to a dated CSV for later review. |

## Quick start

```bash
# build (no Visual Studio needed, uses the in-box C# compiler)
build.cmd

# run (admin recommended for precise ETW mode)
bin\NetAudit.exe
```

UAC will ask for elevation — ETW kernel sessions need it. Without it, NetAudit runs in degraded IO-estimate mode.

Four tabs:

- **Overview** — per-process upload / download totals, current rate, UDP targets.
- **Connections** — live TCP/UDP table with process, state, and outbound flag.
- **Alerts** — rule-triggered events, color-coded, auto-logged to CSV.
- **Settings** — log folder, traffic threshold, system-process alerts, autostart.

## Tech

- C# / WinForms, .NET Framework 4.8
- [Microsoft.Diagnostics.Tracing.TraceEvent](https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent/) for real-time ETW kernel network sessions (TCP/UDP/IP events)
- `iphlpapi` for the connection table
- Single executable + two dependency DLLs, no installer

## Positioning

NetAudit is a **defensive audit tool**: inspect your own machine, a lab box, or a classroom network. It does not intercept, modify, or inject into other processes. It reads.

Not for: surveillance of third parties without consent, bypassing network controls, or anything that would make your sysadmin unhappy.

## Layout

```
NetAudit/
├── MainForm.cs            # WinForms UI, four tabs
├── Program.cs
├── Core/
│   ├── TrafficMonitor.cs      # ETW kernel session + IO fallback
│   ├── ConnectionSampler.cs    # TCP/UDP table polling
│   ├── RuleEngine.cs           # alert rules
│   ├── AuditLogger.cs          # per-day CSV
│   ├── HostsExporter.cs        # IP blacklist + hosts template
│   ├── ProcessResolver.cs      # PID -> name cache
│   └── NativeMethods.cs        # iphlpapi P/Invoke
├── Models/
├── lib/                   # TraceEvent DLLs
└── build.cmd
```

## License

[MIT](LICENSE).

---

If NetAudit helps you catch something phoning home, a ⭐ is appreciated.
