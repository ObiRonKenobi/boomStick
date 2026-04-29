from __future__ import annotations

from core.utils.crossplatform import platform_name
from gui.app import MainWindow


def main() -> None:
    # Force early OS detection so tool selection is consistent per run.
    _ = platform_name()
    app = MainWindow()
    app.mainloop()


if __name__ == "__main__":
    main()

