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

