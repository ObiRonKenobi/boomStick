from __future__ import annotations

import customtkinter as ctk


class ScrollableText(ctk.CTkFrame):
    def __init__(self, master, *, height: int = 240):
        super().__init__(master)
        self.text = ctk.CTkTextbox(self, height=height, wrap="word")
        self.text.pack(fill="both", expand=True)

    def set_text(self, value: str) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", value)
        self.text.configure(state="disabled")

    def append(self, value: str) -> None:
        self.text.configure(state="normal")
        self.text.insert("end", value)
        self.text.see("end")
        self.text.configure(state="disabled")


class CollapsibleSection(ctk.CTkFrame):
    """
    Simple accordion section: a header button toggles a collapsible body frame.
    """

    def __init__(self, master, *, title: str, start_open: bool = False):
        super().__init__(master)
        self._title_base = title
        self._count: int | None = None
        self._open = start_open

        self.header_btn = ctk.CTkButton(self, text=title, anchor="w", command=self.toggle)
        self.header_btn.pack(fill="x", padx=0, pady=(0, 6))

        self.body = ctk.CTkFrame(self)
        self.body_text = ScrollableText(self.body, height=180)
        self.body_text.pack(fill="both", expand=True, padx=8, pady=8)

        if self._open:
            self.body.pack(fill="both", expand=True, padx=0, pady=(0, 10))

    def set_heading(self, title: str, count: int | None = None) -> None:
        self._title_base = title
        self._count = count
        if count is None:
            text = title
        else:
            text = f"{title} ({count})"
        caret = "▼ " if self._open else "► "
        self.header_btn.configure(text=caret + text)

    def set_body(self, text: str) -> None:
        self.body_text.set_text(text)

    def toggle(self) -> None:
        self._open = not self._open
        if self._open:
            self.body.pack(fill="both", expand=True, padx=0, pady=(0, 10))
        else:
            self.body.pack_forget()
        # re-apply heading to update caret
        self.set_heading(self._title_base, self._count)

