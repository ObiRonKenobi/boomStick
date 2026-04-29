from __future__ import annotations

import json
import queue
import threading
from dataclasses import asdict
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Any

import customtkinter as ctk

from core.models import ScanConfig, ScanMode, ScanScope
from core.scanner import scan_worker
from gui.results_display import format_enumeration, format_summary, format_vulnerabilities
from gui.widgets import ScrollableText


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("boomStick")
        self.geometry("900x700")

        self._queue: queue.Queue = queue.Queue()
        self._worker: threading.Thread | None = None
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

        self.summary_box = ScrollableText(self.tabs.tab("Summary"))
        self.summary_box.pack(fill="both", expand=True, padx=10, pady=10)

        self.enum_box = ScrollableText(self.tabs.tab("Enumeration"))
        self.enum_box.pack(fill="both", expand=True, padx=10, pady=10)

        self.vuln_box = ScrollableText(self.tabs.tab("Vulnerabilities"))
        self.vuln_box.pack(fill="both", expand=True, padx=10, pady=10)

        self.summary_box.set_text("Ready.\n")
        self.enum_box.set_text("")
        self.vuln_box.set_text("")

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
        )

        self._cancel.clear()
        self._last_result = None
        self.export_btn.configure(state="disabled")
        self.start_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.progress.set(0.0)
        self.status.configure(text="Starting…")
        self.summary_box.set_text("Running scan…\n")
        self.enum_box.set_text("")
        self.vuln_box.set_text("")

        self._worker = threading.Thread(
            target=scan_worker,
            args=(cfg, self._queue, self._cancel),
            kwargs={"project_root": self.project_root},
            daemon=True,
        )
        self._worker.start()

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
        self.after(100, self._poll_queue)

    def _handle_msg(self, msg: dict[str, Any]) -> None:
        t = msg.get("type")
        if t == "progress":
            pct = float(msg.get("pct", 0.0))
            self.progress.set(max(0.0, min(1.0, pct)))
            self.status.configure(text=str(msg.get("label", "")))
        elif t == "partial":
            # For now we re-render on done; partials can be enhanced to update per-section.
            step = msg.get("step")
            self.status.configure(text=f"{step}…")
        elif t == "error":
            self.status.configure(text=f"Error: {msg.get('message')}")
        elif t == "done":
            self._last_result = msg.get("result")
            if isinstance(self._last_result, dict):
                # Add summary field for formatting convenience.
                try:
                    self._last_result["summary"] = self._last_result.get("summary") or self._compute_summary(self._last_result)
                except Exception:
                    pass
                self.summary_box.set_text(format_summary(self._last_result))
                self.enum_box.set_text(format_enumeration(self._last_result))
                self.vuln_box.set_text(format_vulnerabilities(self._last_result))

            self.start_btn.configure(state="normal")
            self.cancel_btn.configure(state="disabled")
            self.export_btn.configure(state="normal" if self._last_result else "disabled")
            self.progress.set(1.0)
            self.status.configure(text="Idle")

    def _compute_summary(self, result: dict[str, Any]) -> dict[str, Any]:
        # Mirror core.models.ScanResult.summary() but operate on dict.
        enum = result.get("enumeration") or {}
        vuln = result.get("vulnerabilities") or {}
        return {
            "target": result.get("target"),
            "started_at": result.get("started_at"),
            "finished_at": result.get("finished_at"),
            "duration_s": result.get("duration_s"),
            "open_ports": len(enum.get("open_ports") or []),
            "subdomains": len(enum.get("subdomains") or []),
            "findings": len(vuln.get("findings") or []),
            "cves": len(vuln.get("cves") or []),
            "warnings": len(result.get("warnings") or []),
            "errors": len(result.get("errors") or []),
        }

