from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Any

import customtkinter as ctk

from core.models import ScanConfig, ScanMode, ScanScope
from core.scanner import scan_worker
from core.utils.crossplatform import detect_tools, platform_name
from gui.widgets import CollapsibleSection, ScrollableText


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("boomStick")
        self.geometry("900x700")

        self._queue: queue.Queue = queue.Queue()
        self._tools_queue: queue.Queue = queue.Queue()
        self._worker: threading.Thread | None = None
        self._nvd_worker: threading.Thread | None = None
        self._cancel = threading.Event()
        self._last_result: dict[str, Any] | None = None

        ctk.set_appearance_mode("system")
        ctk.set_default_color_theme("dark-blue")

        self._build_ethics_banner()
        self._build_controls()
        self._build_results()
        self._build_status()

        self.after(100, self._poll_queue)

    @property
    def project_root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    def _build_ethics_banner(self) -> None:
        frame = ctk.CTkFrame(self)
        frame.pack(fill="x", padx=10, pady=(10, 0))
        ctk.CTkLabel(
            frame,
            text="Authorized testing only. Use only on systems you own or have explicit written permission to assess.",
            text_color="orange",
            wraplength=860,
            justify="left",
        ).pack(padx=10, pady=10, anchor="w")

    def _build_controls(self) -> None:
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=10, pady=10)

        self.target = ctk.CTkEntry(top, placeholder_text="IP or domain (example: 1.2.3.4 or example.com)")
        self.target.pack(fill="x", padx=10, pady=(10, 8))

        row = ctk.CTkFrame(top)
        row.pack(fill="x", padx=10, pady=(0, 10))

        self.mode = ctk.StringVar(value=ScanMode.QUIET.value)
        ctk.CTkSegmentedButton(row, values=[ScanMode.QUIET.value, ScanMode.LOUD.value], variable=self.mode).pack(
            side="left", padx=(0, 10)
        )

        self.scope = ctk.StringVar(value=ScanScope.BOTH.value)
        ctk.CTkSegmentedButton(row, values=[ScanScope.ENUM.value, ScanScope.VULN.value, ScanScope.BOTH.value], variable=self.scope).pack(
            side="left"
        )

        self.subdomain_strategy = ctk.StringVar(value="bounded_bruteforce")
        ctk.CTkOptionMenu(
            row,
            variable=self.subdomain_strategy,
            values=["bounded_bruteforce", "passive_plus_bruteforce", "external_tools_aggressive"],
        ).pack(side="left", padx=(10, 0))

        self.zap_scan_type = ctk.StringVar(value="spider_plus_passive")
        ctk.CTkOptionMenu(
            row,
            variable=self.zap_scan_type,
            values=["passive_only", "spider_plus_passive", "spider_plus_active"],
        ).pack(side="left", padx=(10, 0))

        self.enable_traceroute = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(row, text="Traceroute", variable=self.enable_traceroute).pack(side="left", padx=(10, 0))

        self.enable_zone_transfer = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            row,
            text="Zone transfer (AXFR)",
            variable=self.enable_zone_transfer,
        ).pack(side="left", padx=(10, 0))

        btns = ctk.CTkFrame(top)
        btns.pack(fill="x", padx=10, pady=(0, 10))

        self.start_btn = ctk.CTkButton(btns, text="Start Scan", command=self._start_scan)
        self.start_btn.pack(side="left", padx=(0, 8))

        self.cancel_btn = ctk.CTkButton(btns, text="Cancel", command=self._cancel_scan, state="disabled")
        self.cancel_btn.pack(side="left", padx=(0, 8))

        self.export_btn = ctk.CTkButton(btns, text="Export JSON", command=self._export_json, state="disabled")
        self.export_btn.pack(side="left")

    def _build_results(self) -> None:
        self.tabs = ctk.CTkTabview(self)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.tabs.add("Summary")
        self.tabs.add("Enumeration")
        self.tabs.add("Vulnerabilities")
        self.tabs.add("Tools")

        # Summary tab: compact overview + collapsible warnings/errors
        self.summary_overview = ScrollableText(self.tabs.tab("Summary"), height=180)
        self.summary_overview.pack(fill="x", expand=False, padx=10, pady=(10, 6))
        self.summary_overview.set_text("Ready.\n")
        self.summary_activity = CollapsibleSection(self.tabs.tab("Summary"), title="Activity log", start_open=True)
        self.summary_activity.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.summary_warnings = CollapsibleSection(self.tabs.tab("Summary"), title="Warnings", start_open=False)
        self.summary_warnings.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.summary_errors = CollapsibleSection(self.tabs.tab("Summary"), title="Errors", start_open=False)
        self.summary_errors.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Enumeration tab: accordion sections
        etab = self.tabs.tab("Enumeration")
        self.enum_ips = CollapsibleSection(etab, title="Resolved IPs", start_open=False)
        self.enum_ips.pack(fill="both", expand=True, padx=10, pady=(10, 6))
        self.enum_dns = CollapsibleSection(etab, title="DNS records", start_open=False)
        self.enum_dns.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.enum_axfr = CollapsibleSection(etab, title="Zone transfer (AXFR)", start_open=False)
        self.enum_axfr.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.enum_subdomains = CollapsibleSection(etab, title="Subdomains", start_open=False)
        self.enum_subdomains.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.enum_ports = CollapsibleSection(etab, title="Open ports", start_open=True)
        self.enum_ports.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.enum_traceroute = CollapsibleSection(etab, title="Traceroute", start_open=False)
        self.enum_traceroute.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Vulnerabilities tab: accordion sections
        vtab = self.tabs.tab("Vulnerabilities")
        self.vuln_findings = CollapsibleSection(vtab, title="Findings", start_open=True)
        self.vuln_findings.pack(fill="both", expand=True, padx=10, pady=(10, 6))
        self.vuln_cves = CollapsibleSection(vtab, title="CVEs", start_open=False)
        self.vuln_cves.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Tools tab: diagnostics for external tools + OS
        ttab = self.tabs.tab("Tools")
        tools_top = ctk.CTkFrame(ttab)
        tools_top.pack(fill="x", padx=10, pady=(10, 6))
        ctk.CTkLabel(tools_top, text="Tool diagnostics (PATH + common locations + BOOMSTICK_* overrides)").pack(
            side="left", padx=10, pady=10
        )
        ctk.CTkButton(tools_top, text="Refresh", command=self._render_tools).pack(side="right", padx=10, pady=10)

        tools_actions = ctk.CTkFrame(ttab)
        tools_actions.pack(fill="x", padx=10, pady=(0, 6))
        ctk.CTkLabel(tools_actions, text="Offline NVD DB:").pack(side="left", padx=(10, 6), pady=10)
        self.nvd_preset = ctk.StringVar(value="quick_recent_modified")
        ctk.CTkOptionMenu(
            tools_actions,
            variable=self.nvd_preset,
            values=[
                "quick_recent_modified",
                "full_last2years_plus_modified",
                "full_last5years_plus_modified",
            ],
        ).pack(side="left", padx=(0, 10), pady=10)
        self.nvd_update_btn = ctk.CTkButton(tools_actions, text="Update NVD DB", command=self._start_nvd_update)
        self.nvd_update_btn.pack(side="left", padx=(0, 10), pady=10)
        self.nvd_status = ctk.CTkLabel(tools_actions, text="Idle")
        self.nvd_status.pack(side="left", padx=10, pady=10)

        self.tools_box = ScrollableText(ttab, height=420)
        self.tools_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._render_tools()

    def _build_status(self) -> None:
        bar = ctk.CTkFrame(self)
        bar.pack(fill="x", padx=10, pady=(0, 10))

        self.progress = ctk.CTkProgressBar(bar)
        self.progress.pack(fill="x", padx=10, pady=(10, 6))
        self.progress.set(0.0)

        self.status = ctk.CTkLabel(bar, text="Idle")
        self.status.pack(anchor="w", padx=12, pady=(0, 10))

    def _start_scan(self) -> None:
        target = self.target.get().strip()
        if not target:
            messagebox.showwarning("boomStick", "Please enter a target (IP or domain).")
            return
        if self._worker and self._worker.is_alive():
            messagebox.showinfo("boomStick", "A scan is already running.")
            return

        cfg = ScanConfig(
            target=target,
            mode=ScanMode(self.mode.get()),
            scope=ScanScope(self.scope.get()),
            subdomain_strategy=self.subdomain_strategy.get(),  # type: ignore[arg-type]
            zap_scan_type=self.zap_scan_type.get(),  # type: ignore[arg-type]
            enable_traceroute=bool(self.enable_traceroute.get()),
            enable_zone_transfer=bool(self.enable_zone_transfer.get()),
        )

        self._cancel.clear()
        self._last_result = None
        self.export_btn.configure(state="disabled")
        self.start_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.progress.set(0.0)
        self.status.configure(text="Starting…")
        self.summary_overview.set_text("Running scan…\n")
        self.summary_activity.set_heading("Activity log", 0)
        self.summary_activity.set_body("")
        self.summary_warnings.set_heading("Warnings", 0)
        self.summary_warnings.set_body("")
        self.summary_errors.set_heading("Errors", 0)
        self.summary_errors.set_body("")
        self._clear_enum()
        self._clear_vuln()

        self._worker = threading.Thread(
            target=scan_worker,
            args=(cfg, self._queue, self._cancel),
            kwargs={"project_root": self.project_root},
            daemon=True,
        )
        self._worker.start()

        # Tools can change during a scan (auto-install). This gives the user a quick baseline.
        self._render_tools()

    def _cancel_scan(self) -> None:
        self._cancel.set()
        self.status.configure(text="Cancelling…")

    def _export_json(self) -> None:
        if not self._last_result:
            return
        path = filedialog.asksaveasfilename(
            title="Export scan results",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
        )
        if not path:
            return
        try:
            Path(path).write_text(json.dumps(self._last_result, indent=2), encoding="utf8")
            messagebox.showinfo("boomStick", "Exported scan results.")
        except Exception as e:
            messagebox.showerror("boomStick", f"Failed to export: {e}")

    def _poll_queue(self) -> None:
        try:
            while True:
                msg = self._queue.get_nowait()
                self._handle_msg(msg)
        except queue.Empty:
            pass

        # Tools background tasks (e.g., offline NVD updater)
        try:
            while True:
                msg = self._tools_queue.get_nowait()
                self._handle_tools_msg(msg)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _handle_msg(self, msg: dict[str, Any]) -> None:
        t = msg.get("type")
        if t == "progress":
            pct = float(msg.get("pct", 0.0))
            self.progress.set(max(0.0, min(1.0, pct)))
            self.status.configure(text=str(msg.get("label", "")))
            # Also append to activity log for traceability.
            label = str(msg.get("label", ""))
            if label and label not in ("Planning", "Done"):
                self._append_activity(f"[status] {label}\n")
        elif t == "partial":
            # For now we re-render on done; partials can be enhanced to update per-section.
            step = msg.get("step")
            payload = msg.get("payload") or {}
            ok = payload.get("ok")
            if ok is True:
                self._append_activity(f"[step-ok] {step}\n")
            elif ok is False:
                self._append_activity(f"[step-fail] {step}: {payload.get('error')}\n")
            self.status.configure(text=f"{step}…")
        elif t == "log":
            self._append_activity(str(msg.get("text", "")))
        elif t == "error":
            self.status.configure(text=f"Error: {msg.get('message')}")
        elif t == "done":
            self._last_result = msg.get("result")
            if isinstance(self._last_result, dict):
                self._render_result(self._last_result)

            self.start_btn.configure(state="normal")
            self.cancel_btn.configure(state="disabled")
            self.export_btn.configure(state="normal" if self._last_result else "disabled")
            self.progress.set(1.0)
            self.status.configure(text="Idle")

    def _append_activity(self, text: str) -> None:
        existing = self.summary_activity.body_text.text.get("1.0", "end")  # type: ignore[attr-defined]
        # Body text is a ScrollableText; use its append helper.
        self.summary_activity.body_text.append(text)
        # Keep the heading count roughly equal to number of lines.
        try:
            lines = int(float(self.summary_activity.body_text.text.index("end-1c").split(".")[0]))  # type: ignore[attr-defined]
            self.summary_activity.set_heading("Activity log", max(0, lines - 1))
        except Exception:
            self.summary_activity.set_heading("Activity log")

    def _handle_tools_msg(self, msg: dict[str, Any]) -> None:
        t = msg.get("type")
        if t == "nvd_log":
            self.tools_box.append(msg.get("text", ""))
        elif t == "nvd_status":
            self.nvd_status.configure(text=str(msg.get("text", "")))
        elif t == "nvd_done":
            self.nvd_status.configure(text="Done")
            self.nvd_update_btn.configure(state="normal")
            self._render_tools()
        elif t == "nvd_error":
            self.nvd_status.configure(text="Error")
            self.nvd_update_btn.configure(state="normal")
            self.tools_box.append("\n[NVD] ERROR: " + str(msg.get("text", "")) + "\n")
            self._render_tools()

    def _clear_enum(self) -> None:
        self.enum_ips.set_heading("Resolved IPs", 0)
        self.enum_ips.set_body("")
        self.enum_dns.set_heading("DNS records", 0)
        self.enum_dns.set_body("")
        self.enum_axfr.set_heading("Zone transfer (AXFR)", 0)
        self.enum_axfr.set_body("")
        self.enum_subdomains.set_heading("Subdomains", 0)
        self.enum_subdomains.set_body("")
        self.enum_ports.set_heading("Open ports", 0)
        self.enum_ports.set_body("")
        self.enum_traceroute.set_heading("Traceroute", 0)
        self.enum_traceroute.set_body("")

    def _clear_vuln(self) -> None:
        self.vuln_findings.set_heading("Findings", 0)
        self.vuln_findings.set_body("")
        self.vuln_cves.set_heading("CVEs", 0)
        self.vuln_cves.set_body("")

    def _render_result(self, result: dict[str, Any]) -> None:
        summary = result.get("summary") or {}
        warnings = result.get("warnings") or []
        errors = result.get("errors") or []
        enum = result.get("enumeration") or {}
        vuln = result.get("vulnerabilities") or {}

        # Overview: show only crucial counts
        overview = [
            f"Target: {summary.get('target', '-')}",
            f"Duration (s): {summary.get('duration_s', '-')}",
            "",
            f"Open ports: {summary.get('open_ports', 0)}",
            f"Subdomains: {summary.get('subdomains', 0)}",
            f"Findings: {summary.get('findings', 0)}",
            f"CVEs: {summary.get('cves', 0)}",
            "",
            f"Warnings: {len(warnings)}",
            f"Errors: {len(errors)}",
        ]
        self.summary_overview.set_text("\n".join(overview).strip() + "\n")

        # Warnings/errors: heading count + concise summaries in body
        self.summary_warnings.set_heading("Warnings", len(warnings))
        self.summary_warnings.set_body("\n".join(f"- {str(w)[:200]}" for w in warnings) + ("\n" if warnings else ""))
        self.summary_errors.set_heading("Errors", len(errors))
        self.summary_errors.set_body("\n".join(f"- {str(e)[:200]}" for e in errors) + ("\n" if errors else ""))

        # Enumeration sections
        ips = enum.get("resolved_ips") or []
        self.enum_ips.set_heading("Resolved IPs", len(ips))
        self.enum_ips.set_body("\n".join(f"- {ip}" for ip in ips) + ("\n" if ips else ""))

        dns_records: dict[str, list[str]] = enum.get("dns_records") or {}
        dns_lines: list[str] = []
        dns_count = 0
        for rrtype, values in dns_records.items():
            if not values:
                continue
            dns_lines.append(f"{rrtype}:")
            for v in values:
                dns_lines.append(f"  - {v}")
                dns_count += 1
        self.enum_dns.set_heading("DNS records", dns_count)
        self.enum_dns.set_body("\n".join(dns_lines).strip() + ("\n" if dns_lines else ""))

        zt = enum.get("zone_transfer") or {}
        zt_attempts = zt.get("attempts") or []
        zt_names = zt.get("discovered_names") or []
        ax_lines: list[str] = []
        if zt:
            ax_lines.append(f"Apex: {zt.get('apex', '-')}")
            ax_lines.append(f"Nodes (zone): {zt.get('discovered_nodes_total', 0)}")
            ax_lines.append(f"RDATA rows (approx): {zt.get('rdata_rows', 0)}")
            ax_lines.append("")
            ax_lines.append("Attempts:")
            for a in zt_attempts[:20]:
                ns = a.get("nameserver", "?")
                where = a.get("where") or "-"
                ok = a.get("ok")
                ax_lines.append(f"  - {ns} @ {where}  ok={ok}")
                if not ok and a.get("error"):
                    ax_lines.append(f"      {str(a.get('error'))[:180]}")
                elif ok:
                    ax_lines.append(
                        f"      names_returned={a.get('names_returned')} "
                        f"nodes_total={a.get('nodes_total')} rdatas={a.get('rdatas')}"
                    )
            if len(zt_attempts) > 20:
                ax_lines.append(f"  ... truncated ({len(zt_attempts) - 20} more attempts)")
            ax_lines.append("")
            ax_lines.append("Discovered names (sample):")
            sample_n = 120
            for n in zt_names[:sample_n]:
                ax_lines.append(f"  - {n}")
            if len(zt_names) > sample_n:
                ax_lines.append(f"  ... truncated ({len(zt_names) - sample_n} more)")
        else:
            ax_lines.append("No zone transfer data (checkbox off or not applicable).")
        self.enum_axfr.set_heading("Zone transfer (AXFR)", len(zt_names) if zt_names else len(zt_attempts))
        self.enum_axfr.set_body("\n".join(ax_lines).strip() + "\n")

        subs = enum.get("subdomains") or []
        self.enum_subdomains.set_heading("Subdomains", len(subs))
        sub_limit = 500
        sub_body = "\n".join(f"- {s}" for s in subs[:sub_limit])
        if len(subs) > sub_limit:
            sub_body += f"\n... truncated ({len(subs) - sub_limit} more)"
        self.enum_subdomains.set_body((sub_body.strip() + "\n") if subs else "")

        ports = enum.get("open_ports") or []
        self.enum_ports.set_heading("Open ports", len(ports))
        port_lines: list[str] = []
        for s in ports:
            port = s.get("port")
            proto = s.get("proto", "tcp")
            name = s.get("name") or "unknown"
            product = s.get("product") or ""
            version = s.get("version") or ""
            extra = " ".join([x for x in [name, product, version] if x]).strip()
            port_lines.append(f"- {port}/{proto} open  {extra}".rstrip())
        self.enum_ports.set_body("\n".join(port_lines).strip() + ("\n" if port_lines else ""))

        tr = enum.get("traceroute") or []
        self.enum_traceroute.set_heading("Traceroute", len(tr))
        tr_lines: list[str] = []
        for hop in tr[:80]:
            hop_n = hop.get("hop")
            raw = hop.get("raw") or hop.get("note") or hop.get("ip") or ""
            tr_lines.append(f"- {hop_n}: {raw}".strip())
        if len(tr) > 80:
            tr_lines.append(f"... truncated ({len(tr) - 80} more)")
        self.enum_traceroute.set_body("\n".join(tr_lines).strip() + ("\n" if tr_lines else ""))

        # Vulnerabilities sections
        findings = vuln.get("findings") or []
        self.vuln_findings.set_heading("Findings", len(findings))
        f_lines: list[str] = []
        for f in findings[:200]:
            sev = f.get("severity", "info")
            title = f.get("title", "Finding")
            url = f.get("url")
            param = f.get("parameter")
            f_lines.append(f"- [{sev}] {title}")
            if url:
                f_lines.append(f"  URL: {url}")
            if param:
                f_lines.append(f"  Parameter: {param}")
            desc = f.get("description")
            if desc:
                f_lines.append(f"  {desc}")
            rec = f.get("recommendation")
            if rec:
                f_lines.append(f"  Recommendation: {rec}")
        if len(findings) > 200:
            f_lines.append(f"... truncated ({len(findings) - 200} more)")
        self.vuln_findings.set_body("\n".join(f_lines).strip() + ("\n" if f_lines else ""))

        cves = vuln.get("cves") or []
        self.vuln_cves.set_heading("CVEs", len(cves))
        c_lines: list[str] = []
        for c in cves[:200]:
            cve = c.get("cve")
            summary_txt = c.get("summary")
            url = c.get("url")
            c_lines.append(f"- {cve}")
            match = c.get("match") or {}
            svc = c.get("service") or {}
            if match.get("query"):
                c_lines.append(f"  Matched query: {match.get('query')}")
            if svc.get("port") or svc.get("name"):
                c_lines.append(
                    f"  Service: {svc.get('port')}/{(svc.get('proto') or 'tcp')} {svc.get('name') or ''} {svc.get('product') or ''} {svc.get('version') or ''}".strip()
                )
            cpes = svc.get("cpes") or match.get("cpes") or []
            if cpes:
                c_lines.append("  CPEs:")
                for cp in cpes[:5]:
                    c_lines.append(f"    - {cp}")
            if summary_txt:
                c_lines.append(f"  {str(summary_txt)[:240]}")
            if url:
                c_lines.append(f"  {url}")
        if len(cves) > 200:
            c_lines.append(f"... truncated ({len(cves) - 200} more)")
        self.vuln_cves.set_body("\n".join(c_lines).strip() + ("\n" if c_lines else ""))

        # If a scan performed installs, tool availability may have changed.
        self._render_tools()

    def _render_tools(self) -> None:
        """
        Show best-effort tool discovery results for the current machine/session.
        This does not modify the system; it only reports what we can locate.
        """
        tools = detect_tools()
        env_keys = [
            "BOOMSTICK_NMAP",
            "BOOMSTICK_DIG",
            "BOOMSTICK_WHOIS",
            "BOOMSTICK_ZAP",
            "BOOMSTICK_ZAP_PORT",
            "BOOMSTICK_ZAP_LOG",
        ]
        import os

        lines: list[str] = []
        lines.append(f"OS: {platform_name()}")
        lines.append("")
        lines.append("Detected tools:")
        lines.append(f"- nmap: {tools.nmap or 'NOT FOUND'}")
        lines.append(f"- dig: {tools.dig or 'NOT FOUND'}")
        lines.append(f"- whois: {tools.whois or 'NOT FOUND'}")
        lines.append(f"- traceroute/tracert: {tools.traceroute or 'NOT FOUND'}")
        lines.append(f"- OWASP ZAP: {tools.zap or 'NOT FOUND'}")
        lines.append("")
        lines.append("Environment overrides:")
        for k in env_keys:
            v = os.environ.get(k)
            if v:
                lines.append(f"- {k}={v}")
        if all(os.environ.get(k) is None for k in env_keys):
            lines.append("- (none set)")
        lines.append("")
        lines.append("Notes:")
        lines.append("- If a tool was just installed, you may need to restart the app or shell so PATH updates take effect.")
        lines.append("- You can always set BOOMSTICK_* env vars to point directly to the tool executable.")

        self.tools_box.set_text("\n".join(lines).strip() + "\n")

    def _nvd_feeds_for_preset(self) -> list[str]:
        preset = self.nvd_preset.get()
        year = datetime.now().year
        if preset == "quick_recent_modified":
            return ["recent", "modified"]
        if preset == "full_last2years_plus_modified":
            return [str(year), str(year - 1), "modified"]
        if preset == "full_last5years_plus_modified":
            return [str(year - i) for i in range(0, 5)] + ["modified"]
        return ["recent", "modified"]

    def _start_nvd_update(self) -> None:
        if self._nvd_worker and self._nvd_worker.is_alive():
            messagebox.showinfo("boomStick", "NVD update is already running.")
            return
        self.nvd_update_btn.configure(state="disabled")
        self.nvd_status.configure(text="Running…")

        # Clear and show header
        self.tools_box.append("\n[NVD] Starting offline DB update…\n")
        feeds = self._nvd_feeds_for_preset()
        db_path = self.project_root / "data" / "nvd.sqlite"
        self.tools_box.append(f"[NVD] DB: {db_path}\n")
        self.tools_box.append(f"[NVD] Feeds: {' '.join(feeds)}\n")

        def worker() -> None:
            try:
                script = self.project_root / "tools" / "update_nvd_db.py"
                cmd = [sys.executable, str(script), "--db", str(db_path), "--feeds", *feeds]
                self._tools_queue.put({"type": "nvd_status", "text": "Downloading/ingesting…"})
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=str(self.project_root),
                )
                assert proc.stdout is not None
                for line in proc.stdout:
                    self._tools_queue.put({"type": "nvd_log", "text": line})
                rc = proc.wait()
                if rc != 0:
                    self._tools_queue.put({"type": "nvd_error", "text": f"Updater exited with code {rc}"})
                else:
                    self._tools_queue.put({"type": "nvd_done"})
            except Exception as e:
                self._tools_queue.put({"type": "nvd_error", "text": str(e)})

        self._nvd_worker = threading.Thread(target=worker, daemon=True)
        self._nvd_worker.start()

