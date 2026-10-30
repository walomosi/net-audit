using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Windows.Forms;
using NetAudit.Core;
using NetAudit.Models;

namespace NetAudit
{
    public class MainForm : Form
    {
        private readonly AppSettings _settings = new AppSettings();
        private readonly ProcessResolver _resolver = new ProcessResolver();
        private readonly TrafficMonitor _traffic;
        private readonly ConnectionSampler _sampler;
        private readonly RuleEngine _rules;
        private readonly AuditLogger _logger;

        private readonly List<AuditEvent> _events = new List<AuditEvent>();
        private readonly List<AuditEvent> _pending = new List<AuditEvent>();
        private readonly object _eventLock = new object();

        private Thread _worker;
        private volatile bool _running;
        private System.Windows.Forms.Timer _uiTimer;
        private Dictionary<int, ProcessTraffic> _prevTotals = new Dictionary<int, ProcessTraffic>();
        private readonly Dictionary<string, int> _connRowIndex = new Dictionary<string, int>();
        private DateTime _prevTime = DateTime.Now;
        private readonly string _iniPath;

        // UI
        private ToolStrip _ts;
        private ToolStripButton _btnToggle;
        private ToolStripButton _btnExportIp;
        private ToolStripButton _btnExportHosts;
        private ToolStripButton _btnOpenLog;
        private ToolStripButton _btnClear;
        private TabControl _tab;
        private DataGridView _gridTraffic;
        private DataGridView _gridConns;
        private DataGridView _gridEvents;
        private StatusStrip _status;
        private ToolStripStatusLabel _lblMode;
        private ToolStripStatusLabel _lblConns;
        private ToolStripStatusLabel _lblEvents;
        private ToolStripStatusLabel _lblState;
        private TextBox _txtLogDir;
        private Button _btnBrowse;
        private NumericUpDown _numRate;
        private CheckBox _chkSystem;
        private CheckBox _chkAutoStart;
        private Button _btnSaveSettings;

        public MainForm()
        {
            _iniPath = Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), "settings.ini");
            LoadSettings();

            _traffic = new TrafficMonitor(_resolver);
            _sampler = new ConnectionSampler(_resolver);
            _rules = new RuleEngine(_settings);
            _logger = new AuditLogger(_settings.LogDirectory);

            _sampler.NewConnection += OnNewConnection;
            _rules.OnEvent += OnRuleEvent;

            InitializeComponent();

            _uiTimer = new System.Windows.Forms.Timer();
            _uiTimer.Interval = _settings.RefreshIntervalMs;
            _uiTimer.Tick += OnUiTick;
            _uiTimer.Start();

            Shown += OnShown;
        }

        private void OnShown(object sender, EventArgs e)
        {
            if (_settings.AutoStart)
            {
                StartMonitoring();
            }
        }

        // ---------- UI build ----------

        private void InitializeComponent()
        {
            Text = "NetAudit - Windows Network Audit";
            ClientSize = new Size(1180, 720);
            MinimumSize = new Size(900, 560);
            StartPosition = FormStartPosition.CenterScreen;

            _ts = new ToolStrip();
            _ts.Dock = DockStyle.Top;
            _btnToggle = new ToolStripButton("Start monitoring");
            _btnToggle.Click += OnToggleClick;
            _btnExportIp = new ToolStripButton("Export suspicious IPs");
            _btnExportIp.Click += OnExportIpClick;
            _btnExportHosts = new ToolStripButton("Export hosts template");
            _btnExportHosts.Click += OnExportHostsClick;
            _btnOpenLog = new ToolStripButton("Open log folder");
            _btnOpenLog.Click += OnOpenLogClick;
            _btnClear = new ToolStripButton("Clear alerts");
            _btnClear.Click += OnClearClick;
            _ts.Items.Add(_btnToggle);
            _ts.Items.Add(new ToolStripSeparator());
            _ts.Items.Add(_btnExportIp);
            _ts.Items.Add(_btnExportHosts);
            _ts.Items.Add(new ToolStripSeparator());
            _ts.Items.Add(_btnOpenLog);
            _ts.Items.Add(_btnClear);

            _tab = new TabControl();
            _tab.Dock = DockStyle.Fill;

            // overview tab
            TabPage pageTraffic = new TabPage("Overview - per-process traffic");
            _gridTraffic = BuildGrid(new string[]
            {
                "Process", "PID", "Upload MB", "Download MB", "Rate MB/s", "UDP target"
            }, new int[] { 160, 70, 110, 110, 110, 220 });
            _gridTraffic.Dock = DockStyle.Fill;
            pageTraffic.Controls.Add(_gridTraffic);
            _tab.TabPages.Add(pageTraffic);

            // connections tab
            TabPage pageConns = new TabPage("Connections");
            _gridConns = BuildGrid(new string[]
            {
                "Process", "PID", "Proto", "Local", "Remote", "State", "First seen", "Last seen", "Outbound"
            }, new int[] { 130, 60, 60, 150, 190, 90, 70, 70, 45 });
            _gridConns.Dock = DockStyle.Fill;
            pageConns.Controls.Add(_gridConns);
            _tab.TabPages.Add(pageConns);

            // alerts tab
            TabPage pageEvents = new TabPage("Alerts");
            _gridEvents = BuildGrid(new string[]
            {
                "Time", "Level", "Process", "PID", "Event", "Detail"
            }, new int[] { 130, 55, 120, 60, 100, 600 });
            _gridEvents.Dock = DockStyle.Fill;
            pageEvents.Controls.Add(_gridEvents);
            _tab.TabPages.Add(pageEvents);

            // settings tab
            TabPage pageSettings = new TabPage("Settings");
            pageSettings.Controls.Add(BuildSettingsPanel());
            _tab.TabPages.Add(pageSettings);

            _status = new StatusStrip();
            _lblMode = new ToolStripStatusLabel("Mode: idle");
            _lblConns = new ToolStripStatusLabel("Connections: 0");
            _lblEvents = new ToolStripStatusLabel("Events: 0");
            _lblState = new ToolStripStatusLabel("Ready");
            _status.Items.Add(_lblMode);
            _status.Items.Add(_lblConns);
            _status.Items.Add(_lblEvents);
            _status.Items.Add(_lblState);

            Controls.Add(_tab);
            Controls.Add(_ts);
            Controls.Add(_status);
        }

        private static DataGridView BuildGrid(string[] headers, int[] widths)
        {
            DataGridView g = new DataGridView();
            g.AllowUserToAddRows = false;
            g.AllowUserToDeleteRows = false;
            g.ReadOnly = true;
            g.RowHeadersVisible = false;
            g.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            g.MultiSelect = false;
            g.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.None;
            for (int i = 0; i < headers.Length; i++)
            {
                DataGridViewTextBoxColumn col = new DataGridViewTextBoxColumn();
                col.HeaderText = headers[i];
                col.Width = widths[i];
                g.Columns.Add(col);
            }
            return g;
        }

        private Control BuildSettingsPanel()
        {
            TableLayoutPanel panel = new TableLayoutPanel();
            panel.Dock = DockStyle.Fill;
            panel.Padding = new Padding(12);
            panel.ColumnCount = 2;
            panel.RowCount = 7;

            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            Label l1 = new Label();
            l1.Text = "Log folder";
            l1.AutoSize = true;
            _txtLogDir = new TextBox();
            _txtLogDir.Text = _settings.LogDirectory;
            _txtLogDir.Dock = DockStyle.Fill;
            _btnBrowse = new Button();
            _btnBrowse.Text = "Browse...";
            _btnBrowse.Click += OnBrowseClick;
            TableLayoutPanel dirRow = new TableLayoutPanel();
            dirRow.ColumnCount = 2;
            dirRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            dirRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
            dirRow.Controls.Add(_txtLogDir, 0, 0);
            dirRow.Controls.Add(_btnBrowse, 1, 0);

            Label l2 = new Label();
            l2.Text = "High-traffic threshold (MB/s)";
            l2.AutoSize = true;
            _numRate = new NumericUpDown();
            _numRate.Minimum = 0.1m;
            _numRate.Maximum = 1000m;
            _numRate.DecimalPlaces = 1;
            _numRate.Value = (decimal)_settings.HighRateMBps;
            _numRate.Width = 120;

            Label l3 = new Label();
            l3.Text = "System-process alerts";
            l3.AutoSize = true;
            _chkSystem = new CheckBox();
            _chkSystem.Text = "Also alert on system processes (svchost / System) - silent by default";
            _chkSystem.Checked = _settings.AlertSystemProcess;

            Label l4 = new Label();
            l4.Text = "Startup";
            l4.AutoSize = true;
            _chkAutoStart = new CheckBox();
            _chkAutoStart.Text = "Start monitoring automatically on launch";
            _chkAutoStart.Checked = _settings.AutoStart;

            _btnSaveSettings = new Button();
            _btnSaveSettings.Text = "Save settings";
            _btnSaveSettings.Width = 100;
            _btnSaveSettings.Click += OnSaveSettingsClick;

            Label about = new Label();
            about.Text =
                "Collection: ETW kernel network events first (per-process bytes in/out); when permissions or environment limit it, falls back to process IO counters (incl. disk IO, approximate, labeled in the UI).\r\n\r\n" +
                "Connections: polls the TCP/UDP table every second; flags new outbound connections, unusual ports, and local listeners on low ports.\r\n\r\n" +
                "Feed your accelerator: the exported suspicious-IP list can feed your block / route rules; hosts only blocks domains - use firewall rules for IPs (the template includes example commands).\r\n\r\n" +
                "Note: run as administrator; results are for reference only and are not a security verdict.";
            about.AutoSize = true;
            about.MaximumSize = new Size(900, 0);

            panel.Controls.Add(l1, 0, 0);
            panel.Controls.Add(dirRow, 1, 0);
            panel.Controls.Add(l2, 0, 1);
            panel.Controls.Add(_numRate, 1, 1);
            panel.Controls.Add(l3, 0, 2);
            panel.Controls.Add(_chkSystem, 1, 2);
            panel.Controls.Add(l4, 0, 3);
            panel.Controls.Add(_chkAutoStart, 1, 3);
            panel.Controls.Add(_btnSaveSettings, 1, 4);
            panel.Controls.Add(about, 0, 5);
            panel.SetColumnSpan(about, 2);

            return panel;
        }

        // ---------- collection ----------

        private void StartMonitoring()
        {
            if (_running) return;
            _running = true;
            _traffic.Start();
            _worker = new Thread(WorkerLoop);
            _worker.IsBackground = true;
            _worker.Start();
            _btnToggle.Text = "Pause monitoring";
            _lblState.Text = "Monitoring";
            UpdateModeLabel();
        }

        private void StopMonitoring()
        {
            _running = false;
            if (_worker != null)
            {
                try { _worker.Join(1500); }
                catch { }
                _worker = null;
            }
            _traffic.Stop();
            _btnToggle.Text = "Start monitoring";
            _lblState.Text = "Paused";
            _lblMode.Text = "Mode: idle";
        }

        private void WorkerLoop()
        {
            while (_running)
            {
                try
                {
                    _sampler.Sample();
                }
                catch
                {
                }
                Thread.Sleep(Math.Max(200, _settings.RefreshIntervalMs));
            }
        }

        private void OnNewConnection(ConnectionInfo c)
        {
            _rules.CheckNewConnection(c);
        }

        private void OnRuleEvent(AuditEvent ev)
        {
            lock (_eventLock)
            {
                _pending.Add(ev);
            }
            _events.Add(ev);
            if (_events.Count > 5000)
            {
                _events.RemoveRange(0, _events.Count - 5000);
            }
        }

        // ---------- UI refresh ----------

        private void OnUiTick(object sender, EventArgs e)
        {
            List<AuditEvent> newEv = new List<AuditEvent>();
            lock (_eventLock)
            {
                if (_pending.Count > 0)
                {
                    newEv.AddRange(_pending);
                    _pending.Clear();
                }
            }
            foreach (AuditEvent ev in newEv)
            {
                AddEventRow(ev);
                _logger.Write(ev);
            }

            RefreshConns();
            RefreshTraffic();

            _lblConns.Text = "Connections: " + _sampler.GetCurrent().Count;
            _lblEvents.Text = "Events: " + _events.Count;
        }

        private void AddEventRow(AuditEvent ev)
        {
            int idx = _gridEvents.Rows.Add(ev.Time.ToString("HH:mm:ss"), ev.Level, ev.Process, ev.Pid, ev.EventType, ev.Detail);
            DataGridViewRow row = _gridEvents.Rows[idx];
            if (ev.Level == "Alert")
            {
                row.DefaultCellStyle.ForeColor = Color.Firebrick;
                row.DefaultCellStyle.Font = new Font(row.DefaultCellStyle.Font, FontStyle.Bold);
            }
            else if (ev.Level == "Warn")
            {
                row.DefaultCellStyle.ForeColor = Color.DarkOrange;
            }
            else
            {
                row.DefaultCellStyle.ForeColor = Color.DimGray;
            }
            if (_gridEvents.Rows.Count > 3000)
            {
                _gridEvents.Rows.RemoveAt(0);
            }
        }

        private void RefreshConns()
        {
            List<ConnectionInfo> conns = _sampler.GetCurrent();
            Dictionary<int, string> udpTargets = _traffic.GetUdpTargetsSnapshot();
            HashSet<string> newKeys = new HashSet<string>();
            _gridConns.SuspendLayout();
            foreach (ConnectionInfo c in conns)
            {
                string remote = c.RemoteAddress;
                if (c.Protocol == ProtocolType.Udp)
                {
                    string t;
                    if (udpTargets.TryGetValue(c.Pid, out t) && !string.IsNullOrEmpty(t))
                    {
                        remote = t + " (UDP)";
                    }
                }
                newKeys.Add(c.Key);
                int idx;
                if (_connRowIndex.TryGetValue(c.Key, out idx) && idx >= 0 && idx < _gridConns.Rows.Count)
                {
                    // incremental update: touch only changed cells
                    DataGridViewRow row = _gridConns.Rows[idx];
                    row.Cells[4].Value = remote;
                    row.Cells[5].Value = c.State;
                    row.Cells[7].Value = c.LastSeen.ToString("HH:mm:ss");
                }
                else
                {
                    idx = _gridConns.Rows.Add(c.ProcessName, c.Pid, c.Protocol.ToString(), c.LocalAddress, remote,
                        c.State, c.FirstSeen.ToString("HH:mm:ss"), c.LastSeen.ToString("HH:mm:ss"),
                        c.IsOutbound ? "Yes" : "No");
                    _connRowIndex[c.Key] = idx;
                }
            }

            // drop vanished connections (delete rows bottom-up to avoid index shifts)
            List<KeyValuePair<string, int>> del = new List<KeyValuePair<string, int>>();
            foreach (KeyValuePair<string, int> kv in _connRowIndex)
            {
                if (!newKeys.Contains(kv.Key)) del.Add(kv);
            }
            if (del.Count > 0)
            {
                del.Sort(delegate(KeyValuePair<string, int> a, KeyValuePair<string, int> b)
                {
                    return b.Value.CompareTo(a.Value);
                });
                foreach (KeyValuePair<string, int> kv in del)
                {
                    if (kv.Value >= 0 && kv.Value < _gridConns.Rows.Count)
                    {
                        _gridConns.Rows.RemoveAt(kv.Value);
                    }
                    _connRowIndex.Remove(kv.Key);
                }
            }
            _gridConns.ResumeLayout();
        }

        private List<ProcessTraffic> BuildTrafficList()
        {
            if (_traffic.UsingEtw)
            {
                Dictionary<int, long> tx;
                Dictionary<int, long> rx;
                _traffic.GetTotals(out tx, out rx);
                HashSet<int> pids = new HashSet<int>();
                foreach (int p in tx.Keys) pids.Add(p);
                foreach (int p in rx.Keys) pids.Add(p);

                DateTime now = DateTime.Now;
                double dt = (now - _prevTime).TotalSeconds;
                if (dt <= 0) dt = 0.001;

                List<ProcessTraffic> list2 = new List<ProcessTraffic>();
                foreach (int pid in pids)
                {
                    ProcessTraffic pt = new ProcessTraffic();
                    pt.Pid = pid;
                    pt.Name = _resolver.GetName(pid);
                    long v;
                    if (tx.TryGetValue(pid, out v)) pt.TxBytes = v;
                    if (rx.TryGetValue(pid, out v)) pt.RxBytes = v;
                    ProcessTraffic prev;
                    if (_prevTotals.TryGetValue(pid, out prev))
                    {
                        long dtx = pt.TxBytes - prev.TxBytes;
                        long drx = pt.RxBytes - prev.RxBytes;
                        if (dtx < 0) dtx = 0;
                        if (drx < 0) drx = 0;
                        pt.RateBytesPerSec = (dtx + drx) / dt;
                    }
                    list2.Add(pt);
                }
                _prevTotals = new Dictionary<int, ProcessTraffic>();
                foreach (ProcessTraffic pt in list2)
                {
                    _prevTotals[pt.Pid] = pt;
                }
                _prevTime = now;
                return list2;
            }
            else
            {
                // non-ETW: no byte deltas, use estimated instantaneous rate
                Dictionary<int, double> io = _traffic.EstimateIoSnapshot();
                List<ProcessTraffic> list = new List<ProcessTraffic>();
                foreach (KeyValuePair<int, double> kv in io)
                {
                    ProcessTraffic pt = new ProcessTraffic();
                    pt.Pid = kv.Key;
                    pt.Name = _resolver.GetName(kv.Key);
                    pt.RateBytesPerSec = kv.Value;
                    list.Add(pt);
                }
                return list;
            }
        }

        private void RenderTrafficGrid(List<ProcessTraffic> list)
        {
            bool etw = _traffic.UsingEtw;
            list.Sort(delegate(ProcessTraffic a, ProcessTraffic b)
            {
                return b.RateBytesPerSec.CompareTo(a.RateBytesPerSec);
            });

            _gridTraffic.SuspendLayout();
            _gridTraffic.Rows.Clear();
            int max = list.Count < 80 ? list.Count : 80;
            Dictionary<int, string> udpTargets = _traffic.GetUdpTargetsSnapshot();
            for (int i = 0; i < max; i++)
            {
                ProcessTraffic pt = list[i];
                string udp = "";
                string t;
                if (udpTargets.TryGetValue(pt.Pid, out t)) udp = t;
                _gridTraffic.Rows.Add(pt.Name, pt.Pid,
                    etw ? pt.TxMB.ToString("0.0") : "-",
                    etw ? pt.RxMB.ToString("0.0") : "-",
                    pt.RateMBps.ToString("0.00"),
                    string.IsNullOrEmpty(udp) ? "" : udp);
            }
            _gridTraffic.ResumeLayout();
        }

        private void RefreshTraffic()
        {
            List<ProcessTraffic> list = BuildTrafficList();
            RenderTrafficGrid(list);
            if (_traffic.UsingEtw)
            {
                _rules.CheckHighTraffic(list);
            }
        }

        // ---------- event handlers ----------

        private void OnToggleClick(object sender, EventArgs e)
        {
            if (_running) StopMonitoring();
            else StartMonitoring();
        }

        private void OnExportIpClick(object sender, EventArgs e)
        {
            SaveFileDialog dlg = new SaveFileDialog();
            dlg.Title = "Export suspicious IP list";
            dlg.Filter = "Text files (*.txt)|*.txt";
            dlg.FileName = "suspicious_ips_" + DateTime.Now.ToString("yyyyMMdd_HHmm") + ".txt";
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            try
            {
                string content = HostsExporter.BuildIpBlacklist(_events, _sampler.GetCurrent());
                File.WriteAllText(dlg.FileName, content, System.Text.Encoding.UTF8);
                MessageBox.Show(this, "Exported to:\n" + dlg.FileName, "Export complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Export failed: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnExportHostsClick(object sender, EventArgs e)
        {
            SaveFileDialog dlg = new SaveFileDialog();
            dlg.Title = "Export hosts block template";
            dlg.Filter = "Text files (*.txt)|*.txt|Hosts file (*.hosts)|*.hosts";
            dlg.FileName = "hosts_block_template_" + DateTime.Now.ToString("yyyyMMdd_HHmm") + ".txt";
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            try
            {
                string content = HostsExporter.BuildHostsTemplate(_events, _sampler.GetCurrent());
                File.WriteAllText(dlg.FileName, content, System.Text.Encoding.UTF8);
                MessageBox.Show(this, "Exported to:\n" + dlg.FileName + "\n\nNote: hosts only blocks domains; use the firewall commands in the template to block IPs.",
                    "Export complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Export failed: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnOpenLogClick(object sender, EventArgs e)
        {
            try
            {
                if (!Directory.Exists(_logger.DirectoryPath)) Directory.CreateDirectory(_logger.DirectoryPath);
                Process.Start("explorer.exe", _logger.DirectoryPath);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Cannot open log folder: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnClearClick(object sender, EventArgs e)
        {
            _gridEvents.Rows.Clear();
            lock (_eventLock)
            {
                _events.Clear();
                _pending.Clear();
            }
            _rules.ClearNotified();
            _lblEvents.Text = "Events: 0";
        }

        private void OnBrowseClick(object sender, EventArgs e)
        {
            FolderBrowserDialog dlg = new FolderBrowserDialog();
            dlg.Description = "Choose log folder";
            dlg.SelectedPath = _txtLogDir.Text;
            if (dlg.ShowDialog(this) == DialogResult.OK)
            {
                _txtLogDir.Text = dlg.SelectedPath;
            }
        }

        private void OnSaveSettingsClick(object sender, EventArgs e)
        {
            _settings.HighRateMBps = (double)_numRate.Value;
            _settings.LogDirectory = _txtLogDir.Text.Trim();
            _settings.AlertSystemProcess = _chkSystem.Checked;
            _settings.AutoStart = _chkAutoStart.Checked;
            SaveSettings();
            _logger.DirectoryPath = _settings.LogDirectory;
            MessageBox.Show(this, "Settings saved.\nThreshold applies to the next alert evaluation; log folder takes effect immediately.",
                "Saved", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void UpdateModeLabel()
        {
            if (!_running)
            {
                _lblMode.Text = "Mode: idle";
                return;
            }
            _lblMode.Text = _traffic.UsingEtw
                ? "Mode: ETW precise"
                : "Mode: IO estimate (degraded, incl. disk IO, approximate)";
        }

        // ---------- settings persistence ----------

        private void LoadSettings()
        {
            try
            {
                if (File.Exists(_iniPath))
                {
                    foreach (string line in File.ReadAllLines(_iniPath))
                    {
                        if (line.StartsWith("HighRateMBps="))
                        {
                            double v;
                            if (double.TryParse(line.Substring(13), out v)) _settings.HighRateMBps = v;
                        }
                        else if (line.StartsWith("LogDirectory="))
                        {
                            string d = line.Substring(13);
                            if (!string.IsNullOrEmpty(d)) _settings.LogDirectory = d;
                        }
                        else if (line.StartsWith("AlertSystemProcess="))
                        {
                            _settings.AlertSystemProcess = line.EndsWith("True");
                        }
                        else if (line.StartsWith("AutoStart="))
                        {
                            _settings.AutoStart = line.EndsWith("True");
                        }
                    }
                }
            }
            catch
            {
            }
            if (string.IsNullOrEmpty(_settings.LogDirectory))
            {
                _settings.LogDirectory = Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), "audit_logs");
            }
        }

        private void SaveSettings()
        {
            try
            {
                List<string> lines = new List<string>();
                lines.Add("HighRateMBps=" + _settings.HighRateMBps.ToString("0.0"));
                lines.Add("LogDirectory=" + _settings.LogDirectory);
                lines.Add("AlertSystemProcess=" + _settings.AlertSystemProcess);
                lines.Add("AutoStart=" + _settings.AutoStart);
                File.WriteAllLines(_iniPath, lines, System.Text.Encoding.UTF8);
            }
            catch
            {
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            _running = false;
            try
            {
                if (_uiTimer != null) _uiTimer.Stop();
            }
            catch
            {
            }
            _traffic.Stop();
            base.OnFormClosing(e);
        }
    }
}
