"""Interactive, synthetic RAM-layout and malware-scan demonstration.

Run this module directly to launch a three-scene Tkinter visual. The scenes
compare contiguous and non-contiguous frame layouts and demonstrate a
page-aware scan for private, writable-executable memory without file backing.
All process and RAM contents are illustrative data; this program does not
acquire, inspect, or modify live system memory.

Run with ``--self-test`` to validate the modeled layouts, or with
``--fullscreen`` to start in presentation mode.
"""

from __future__ import annotations

import argparse
import tkinter as tk
from dataclasses import dataclass


BG = "#0b0e13"
PANEL = "#11161e"
PANEL_ALT = "#151c26"
LINE = "#27313e"
TEXT = "#e7edf5"
MUTED = "#91a0b2"
DIM = "#657286"
GREEN = "#54d6a0"
RED = "#ff6877"
AMBER = "#f2bd68"
BLUE = "#79aaff"
FONT = "Segoe UI"

WIDTH = 1180
HEIGHT = 740
FRAME_COUNT = 16


@dataclass(frozen=True)
class Frame:
    """Describe one illustrative physical frame and its mapped process page.

    Attributes:
        owner: Process label that owns the frame, or ``FREE``/``KERNEL``.
        page: Mapped page name shown in the diagram.
        permissions: Display permissions such as ``R-X``, ``R-W``, or ``RWX``.
        backing: Whether the contents are image-backed or lack file backing.
    """

    owner: str
    page: str
    permissions: str
    backing: str

    @property
    def suspicious(self) -> bool:
        """Return whether the frame is executable, private, and unbacked."""
        return self.permissions == "RWX" and self.backing == "NONE"

def contiguous_layout() -> tuple[Frame, ...]:
    """Build sample RAM where the broker's pages occupy adjacent frames."""
    frames = [Frame("FREE", "—", "—", "—") for _ in range(FRAME_COUNT)]
    for index in range(4, 10):
        frames[index] = Frame("BROKER", f"PAGE {index - 3}", "R-X", "IMAGE")
    frames[7] = Frame("BROKER", "INJECTED", "RWX", "NONE")
    frames[0] = Frame("KERNEL", "SYSTEM", "R-X", "IMAGE")
    frames[12] = Frame("BROWSER", "PAGE 1", "R-W", "IMAGE")
    frames[13] = Frame("BROWSER", "PAGE 2", "R-W", "IMAGE")
    return tuple(frames)


def scattered_layout() -> tuple[Frame, ...]:
    """Build sample RAM where the same broker pages occupy separated frames."""
    frames = [Frame("FREE", "—", "—", "—") for _ in range(FRAME_COUNT)]
    mapped_pages = {
        1: Frame("BROKER", "PAGE 1", "R-X", "IMAGE"),
        4: Frame("BROKER", "PAGE 2", "R-X", "IMAGE"),
        6: Frame("BROKER", "PAGE 3", "R-X", "IMAGE"),
        8: Frame("BROKER", "INJECTED", "RWX", "NONE"),
        11: Frame("BROKER", "PAGE 5", "R-X", "IMAGE"),
        14: Frame("BROKER", "PAGE 6", "R-X", "IMAGE"),
    }
    for index, frame in mapped_pages.items():
        frames[index] = frame
    frames[0] = Frame("KERNEL", "SYSTEM", "R-X", "IMAGE")
    frames[3] = Frame("BROWSER", "PAGE 1", "R-W", "IMAGE")
    frames[10] = Frame("BROWSER", "PAGE 2", "R-W", "IMAGE")
    return tuple(frames)


CONTIGUOUS = contiguous_layout()
SCATTERED = scattered_layout()
SCANNED_CONTIGUOUS = tuple(i for i, frame in enumerate(CONTIGUOUS) if frame.owner == "BROKER")
SCANNED_SCATTERED = tuple(i for i, frame in enumerate(SCATTERED) if frame.owner == "BROKER")


class RamLayoutDemo:
    """Render the comparison, animate scans, and handle presentation controls.

    Drawing methods use a fixed logical coordinate system. Each render scales
    and centers that canvas in the current window so the diagram adapts to
    different window sizes and display resolutions.

    Args:
        root: Tk root window that owns the demo canvas and event loop.
    """

    scene_count = 3

    def __init__(self, root: tk.Tk) -> None:
        """Create the window, bind controls, and begin scanning scene one."""
        self.root = root
        self.root.title("RAM Layout & Malware Scan")
        self.root.configure(bg=BG)
        self.root.resizable(True, True)
        self.root.geometry(f"{WIDTH}x{HEIGHT}")
        self.root.minsize(900, 560)
        self.canvas = tk.Canvas(root, bg=BG, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.scene = 0
        self.scanned: set[int] = set()
        self.scan_order: tuple[int, ...] = ()
        self.scan_position = 0
        self.scan_generation = 0
        self.scale_factor = 1.0
        self.offset_x = 0.0
        self.offset_y = 0.0
        self.fullscreen = False
        self._resize_job: str | None = None
        self.exit_bounds = (1050, 30, 1124, 66)
        self.restart_bounds = (894, 30, 1038, 66)
        self.next_bounds = (1002, 650, 1124, 696)
        self.canvas.bind("<Button-1>", self.on_click)
        self.canvas.bind("<Configure>", self.on_resize)
        self.root.bind("<Right>", lambda _event: self.next_scene())
        self.root.bind("<BackSpace>", lambda _event: self.restart())
        self.root.bind("<F11>", lambda _event: self.toggle_fullscreen())
        self.root.bind("<Escape>", lambda _event: self.leave_fullscreen())
        self.root.protocol("WM_DELETE_WINDOW", self.exit_demo)
        self.start_scene_scan()

    def rect(
        self,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
        fill: str,
        outline: str = "",
        width: int = 1,
    ) -> None:
        """Draw a rectangle in the canvas's unscaled logical coordinates."""
        self.canvas.create_rectangle(
            x1, y1, x2, y2, fill=fill, outline=outline, width=width
        )

    def text(
        self,
        x: int,
        y: int,
        value: str,
        size: int = 11,
        color: str = TEXT,
        weight: str = "normal",
        anchor: str = "w",
        family: str = FONT,
    ) -> None:
        """Draw text using a font size that follows the current canvas scale."""
        self.canvas.create_text(
            x,
            y,
            text=value,
            fill=color,
            font=(family, max(6, round(size * self.scale_factor)), weight),
            anchor=anchor,
        )

    def button(self, bounds: tuple[int, int, int, int], label: str, primary: bool = False) -> None:
        """Draw a labeled button at its logical-coordinate bounds."""
        x1, y1, x2, y2 = bounds
        fill = GREEN if primary else PANEL_ALT
        foreground = BG if primary else MUTED
        self.rect(x1, y1, x2, y2, fill, LINE if not primary else "")
        self.text((x1 + x2) // 2, (y1 + y2) // 2, label, 9, foreground, "bold", "center")

    def draw(self) -> None:
        """Redraw the current scene and scale it to fit the window."""
        self.canvas.delete("all")
        viewport_width = max(self.canvas.winfo_width(), 1)
        viewport_height = max(self.canvas.winfo_height(), 1)
        self.scale_factor = min(viewport_width / WIDTH, viewport_height / HEIGHT)
        self.offset_x = (viewport_width - WIDTH * self.scale_factor) / 2
        self.offset_y = (viewport_height - HEIGHT * self.scale_factor) / 2
        self.draw_header()
        if self.scene < 2:
            self.draw_layout_scene()
        else:
            self.draw_comparison_scene()
        self.draw_controls()
        self.canvas.scale("all", 0, 0, self.scale_factor, self.scale_factor)
        self.canvas.move("all", self.offset_x, self.offset_y)

    def on_resize(self, _event: tk.Event) -> None:
        """Debounce resize events so the canvas is redrawn once per resize."""
        if self._resize_job is not None:
            self.root.after_cancel(self._resize_job)
        self._resize_job = self.root.after_idle(self.redraw_after_resize)

    def redraw_after_resize(self) -> None:
        """Clear the pending resize callback and redraw at the current size."""
        self._resize_job = None
        self.draw()

    def toggle_fullscreen(self) -> None:
        """Toggle borderless fullscreen mode with the F11 key."""
        self.fullscreen = not self.fullscreen
        self.root.attributes("-fullscreen", self.fullscreen)

    def leave_fullscreen(self) -> None:
        """Return from fullscreen mode with Escape."""
        if self.fullscreen:
            self.fullscreen = False
            self.root.attributes("-fullscreen", False)

    def draw_header(self) -> None:
        """Render the title, scene indicator, and navigation buttons."""
        self.rect(0, 0, WIDTH, 1, LINE)
        self.text(56, 35, "RAM LAYOUT  /  MEMORY TRIAGE", 10, MUTED, "bold")
        self.text(56, 91, "Find the payload, wherever it lands.", 27, TEXT, "bold")
        self.text(
            57,
            122,
            "Same scan strategy. Two attacks. Contiguous and scattered RAM.",
            11,
            MUTED,
        )
        self.button(self.restart_bounds, "RESTART")
        self.button(self.exit_bounds, "EXIT")
        self.rect(56, 151, WIDTH - 56, 152, LINE)
        for index in range(self.scene_count):
            cx = 62 + index * 22
            color = GREEN if index == self.scene else DIM
            self.canvas.create_oval(cx, 168, cx + 8, 176, fill=color, outline="")
        labels = ("01  CONTIGUOUS", "02  NON-CONTIGUOUS", "03  WHY IT WORKS")
        self.text(140, 172, labels[self.scene], 9, GREEN, "bold")

    def draw_layout_scene(self) -> None:
        """Render a frame map and its changing scan progress or finding."""
        panel_x, panel_y, panel_w, panel_h = 56, 195, 1068, 326
        self.rect(panel_x, panel_y, panel_x + panel_w, panel_y + panel_h, PANEL, LINE)

        if self.scene == 0:
            title = "One process occupies one continuous run of physical frames."
            explanation = (
                "The scan checks every frame in the process span. One private, "
                "writable + executable page has no file backing."
            )
            layout = CONTIGUOUS
            map_label = "CONTIGUOUS  ·  BROKER PAGES 1–6"
            map_color = BLUE
        else:
            title = "The same process pages are spread across physical RAM."
            explanation = (
                "A page-table walk follows the process's mapped frames across gaps; "
                "it does not assume adjacent addresses."
            )
            layout = SCATTERED
            map_label = "NON-CONTIGUOUS  ·  FOLLOW BROKER PAGE MAP"
            map_color = AMBER

        self.text(panel_x + 24, panel_y + 28, title, 16, TEXT, "bold")
        self.text(panel_x + 24, panel_y + 56, explanation, 10, MUTED)
        self.text(panel_x + 24, panel_y + 91, map_label, 9, map_color, "bold")
        self.text(
            panel_x + panel_w - 24,
            panel_y + 91,
            "PHYSICAL RAM  /  FRAME MAP",
            9,
            DIM,
            "bold",
            "e",
        )
        self.draw_frames(
            layout,
            self.scan_order,
            panel_x + 24,
            panel_y + 112,
            panel_w - 48,
        )

        self.draw_scan_detail(layout)

    def draw_scan_detail(self, layout: tuple[Frame, ...]) -> None:
        """Show the active frame during a scan, then explain its result."""
        panel_x, panel_y = 56, 540
        self.rect(panel_x, panel_y, 1124, 624, PANEL, LINE)
        if self.scan_position < len(self.scan_order):
            frame_index = (
                self.scan_order[self.scan_position - 1]
                if self.scan_position
                else self.scan_order[0]
            )
            frame = layout[frame_index]
            page_name = frame.page.lower().replace("injected", "injected page")
            contiguous = self.scene == 0
            stage = "CONTIGUOUS SCAN" if contiguous else "FOLLOWING PAGE MAP"
            location = f"Frame {frame_index:02}  ·  {page_name}  ·  {frame.permissions}  ·  {frame.backing}"
            if contiguous:
                detail = "Check each frame in the process span."
            else:
                detail = f"Mapped frame {self.scan_position} of {len(self.scan_order)}; gaps are skipped."
            accent = BLUE if contiguous else AMBER
            self.text(panel_x + 22, panel_y + 25, stage, 9, accent, "bold")
            self.text(panel_x + 22, panel_y + 54, location, 10, TEXT, "bold", family="Consolas")
            self.text(1098, panel_y + 25, f"{self.scan_position}/{len(self.scan_order)} CHECKED", 9, MUTED, "bold", "e")
            self.text(1098, panel_y + 54, detail, 9, MUTED, anchor="e")
            return

        frame_index = next(i for i in self.scan_order if layout[i].suspicious)
        self.text(panel_x + 22, panel_y + 25, f"FINDING  ·  FRAME {frame_index:02}", 9, RED, "bold")
        self.text(
            panel_x + 22,
            panel_y + 54,
            "Injected page: PRIVATE  +  RWX  +  NO FILE BACKING",
            10,
            TEXT,
            "bold",
        )
        result = (
            "Matched within contiguous process span."
            if self.scene == 0
            else "Matched via page map across non-adjacent frames."
        )
        self.text(1098, panel_y + 25, "FLAG FOR REVIEW", 9, RED, "bold", "e")
        self.text(1098, panel_y + 54, result, 9, MUTED, anchor="e")

    def draw_frames(
        self,
        layout: tuple[Frame, ...],
        scan_order: tuple[int, ...],
        x: int,
        y: int,
        width: int,
    ) -> None:
        """Draw the physical frame strip and highlight frames already scanned."""
        gap = 7
        cell_w = (width - gap * (FRAME_COUNT - 1)) // FRAME_COUNT
        cell_h = 130
        for index, frame in enumerate(layout):
            x1 = x + index * (cell_w + gap)
            scanned = index in self.scanned
            suspicious = scanned and frame.suspicious
            is_process_page = frame.owner == "BROKER"
            fill = "#27181f" if suspicious else PANEL_ALT if is_process_page else "#0d1117"
            outline = RED if suspicious else BLUE if scanned and is_process_page else LINE
            self.rect(x1, y, x1 + cell_w, y + cell_h, fill, outline, 2)
            self.text(x1 + cell_w // 2, y + 15, f"{index:02}", 9, MUTED, "bold", "center", "Consolas")
            if frame.owner == "BROKER":
                owner_label, owner_color = "BROKER", BLUE
            elif frame.owner == "FREE":
                owner_label, owner_color = "FREE", DIM
            elif frame.owner == "KERNEL":
                owner_label, owner_color = "OS", MUTED
            else:
                owner_label, owner_color = "OTHER", MUTED
            self.text(x1 + cell_w // 2, y + 43, owner_label, 8, owner_color, "bold", "center")
            page_color = RED if suspicious else TEXT if is_process_page else DIM
            page_label = "INJECTED" if frame.suspicious else frame.page
            self.text(x1 + cell_w // 2, y + 66, page_label, 7, page_color, "bold" if suspicious else "normal", "center")
            permission_color = RED if frame.permissions == "RWX" else GREEN if scanned and is_process_page else DIM
            self.text(x1 + cell_w // 2, y + 89, frame.permissions, 8, permission_color, "bold", "center", "Consolas")
            backing_color = AMBER if frame.backing == "NONE" else DIM
            self.text(x1 + cell_w // 2, y + 110, frame.backing, 7, backing_color, "bold" if frame.backing == "NONE" else "normal", "center")
            if scanned:
                self.canvas.create_oval(
                    x1 + cell_w // 2 - 3,
                    y + 121,
                    x1 + cell_w // 2 + 3,
                    y + 127,
                    fill=RED if suspicious else GREEN,
                    outline="",
                )

        self.text(x, y + cell_h + 19, "FRAME  ·  OWNER  ·  PAGE  ·  PERMISSIONS  ·  BACKING", 8, DIM)
        if self.scene == 1:
            self.text(
                x + width,
                y + cell_h + 19,
                f"PAGE MAP: {', '.join(f'{i:02}' for i in scan_order)}",
                8,
                AMBER,
                "bold",
                "e",
                "Consolas",
            )

    def draw_comparison_scene(self) -> None:
        """Compare completed scans and explain why following mapped pages works."""
        x, y = 56, 195
        self.text(x + 4, y + 12, "The allocation strategy changes placement—not the evidence rule.", 16, TEXT, "bold")
        self.text(x + 4, y + 39, "A page-aware scan catches the same injected page in both layouts.", 10, MUTED)

        self.draw_comparison_card(
            56,
            256,
            "CONTIGUOUS",
            "One address span",
            "Frames 04–09",
            "6 / 6 frames inspected",
            "1 suspicious page flagged",
            BLUE,
            "07",
        )
        self.draw_comparison_card(
            602,
            256,
            "NON-CONTIGUOUS",
            "Mapped pages, scattered",
            "Frames 01 · 04 · 06 · 08 · 11 · 14",
            "6 / 6 mapped frames inspected",
            "1 suspicious page flagged",
            AMBER,
            "08",
        )
        self.rect(56, 501, 1124, 624, "#14221e", LINE)
        self.text(78, 527, "WHY THIS WORKS", 9, GREEN, "bold")
        self.text(
            78,
            553,
            "Follow the process page map, then test each mapped region for private + RWX + no file backing.",
            11,
            TEXT,
        )
        self.text(
            78,
            584,
            "Non-contiguous pages do not hide the payload from a page-aware scan; adjacency is not required.",
            10,
            MUTED,
        )
        self.text(
            78,
            609,
            "The layout alone does not detect malware—the region scan does. This demo uses synthetic RAM.",
            9,
            AMBER,
        )

    def draw_comparison_card(
        self,
        x: int,
        y: int,
        heading: str,
        subtitle: str,
        address_line: str,
        scanned_line: str,
        result_line: str,
        accent: str,
        flagged_frame: str,
    ) -> None:
        """Draw one side of the final contiguous/non-contiguous comparison."""
        width, height = 522, 216
        self.rect(x, y, x + width, y + height, PANEL, LINE)
        self.text(x + 20, y + 24, heading, 10, accent, "bold")
        self.text(x + 20, y + 51, subtitle, 15, TEXT, "bold")
        self.text(x + 20, y + 83, address_line, 9, MUTED, family="Consolas")
        self.rect(x + 20, y + 101, x + width - 20, y + 102, LINE)
        self.text(x + 20, y + 127, scanned_line, 10, TEXT)
        self.text(x + 20, y + 157, result_line, 10, RED, "bold")
        self.text(
            x + width - 20,
            y + 187,
            f"FLAGGED  →  FRAME {flagged_frame}",
            9,
            RED,
            "bold",
            "e",
            "Consolas",
        )

    def draw_controls(self) -> None:
        """Draw the synthetic-data notice and scene-advance button."""
        self.rect(56, 637, WIDTH - 56, 638, LINE)
        self.text(56, 673, "SYNTHETIC SNAPSHOT  ·  NO LIVE MEMORY ACCESS", 8, DIM, "bold")
        self.text(858, 673, "NEXT  →" if self.scene < self.scene_count - 1 else "END", 9, DIM, "bold", "e")
        self.button(self.next_bounds, "NEXT  →", primary=self.scene < self.scene_count - 1)
        if self.scene == self.scene_count - 1:
            self.rect(*self.next_bounds, fill=PANEL_ALT, outline=LINE)
            self.text(
                (self.next_bounds[0] + self.next_bounds[2]) // 2,
                (self.next_bounds[1] + self.next_bounds[3]) // 2,
                "END",
                9,
                DIM,
                "bold",
                "center",
            )

    def start_scene_scan(self) -> None:
        """Reset and animate the scan associated with the current scene."""
        self.scan_generation += 1
        generation = self.scan_generation
        self.scanned.clear()
        self.scan_position = 0
        if self.scene == 0:
            self.scan_order = SCANNED_CONTIGUOUS
        elif self.scene == 1:
            self.scan_order = SCANNED_SCATTERED
        else:
            self.scan_order = ()
            self.draw()
            return
        self.draw()
        self.root.after(100, lambda: self.scan_next_frame(generation))

    def scan_next_frame(self, generation: int) -> None:
        """Visit the next mapped frame unless a later scene invalidated this scan."""
        if generation != self.scan_generation or self.scene >= 2:
            return
        if self.scan_position >= len(self.scan_order):
            self.draw()
            return
        self.scanned.add(self.scan_order[self.scan_position])
        self.scan_position += 1
        self.draw()
        self.root.after(220, lambda: self.scan_next_frame(generation))

    def next_scene(self) -> None:
        """Advance to the next scene, stopping at the comparison summary."""
        if self.scene >= self.scene_count - 1:
            return
        self.scene += 1
        self.start_scene_scan()

    def restart(self) -> None:
        """Return to the first scene and replay its scan."""
        self.scene = 0
        self.start_scene_scan()

    def on_click(self, event: tk.Event) -> None:
        """Convert a screen click into logical coordinates and dispatch it."""
        x = (event.x - self.offset_x) / self.scale_factor
        y = (event.y - self.offset_y) / self.scale_factor
        if self.contains(self.exit_bounds, x, y):
            self.exit_demo()
        elif self.contains(self.restart_bounds, x, y):
            self.restart()
        elif self.contains(self.next_bounds, x, y):
            self.next_scene()

    def exit_demo(self) -> None:
        """Close the demonstration window."""
        self.root.destroy()

    @staticmethod
    def contains(bounds: tuple[int, int, int, int], x: float, y: float) -> bool:
        """Return whether a point in logical coordinates lies inside bounds."""
        x1, y1, x2, y2 = bounds
        return x1 <= x <= x2 and y1 <= y <= y2


def self_test() -> None:
    """Assert that page-aware scans find the injected page in both layouts."""
    assert len(SCANNED_CONTIGUOUS) == 6
    assert len(SCANNED_SCATTERED) == 6
    contiguous_findings = [CONTIGUOUS[i] for i in SCANNED_CONTIGUOUS if CONTIGUOUS[i].suspicious]
    scattered_findings = [SCATTERED[i] for i in SCANNED_SCATTERED if SCATTERED[i].suspicious]
    assert len(contiguous_findings) == 1
    assert len(scattered_findings) == 1
    assert contiguous_findings[0].page == scattered_findings[0].page == "INJECTED"
    assert SCANNED_SCATTERED == (1, 4, 6, 8, 11, 14)
    print("Self-test passed: page-aware scans find the injected page in both layouts.")


def main() -> None:
    """Parse command-line options and launch the GUI or model self-test."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="validate both simulated layouts")
    parser.add_argument(
        "--fullscreen",
        action="store_true",
        help="start in borderless fullscreen presentation mode",
    )
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    root = tk.Tk()
    demo = RamLayoutDemo(root)
    if args.fullscreen:
        demo.toggle_fullscreen()
    root.mainloop()


if __name__ == "__main__":
    main()
