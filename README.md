# Memory Management Demo

## Purpose

A dark-mode, three-scene visual for demonstrating a memory-forensics scan
against **synthetic RAM layouts**. It illustrates that contiguous versus
non-contiguous physical placement changes how a process's pages appear in RAM,
but a scan that follows the process page map can inspect both layouts.

The simulated scan flags a private page that is writable, executable, and has
no file backing. This is an illustrative anomaly to review, not proof of
malware. The allocation layout by itself does not detect malicious code.

> This application does not acquire, inspect, or modify live system memory.
> All process names, frame numbers, permissions, and findings are fabricated.

## Run

From this directory:

```powershell
python memory_triage_demo.py
```

Start directly in fullscreen presentation mode:

```powershell
python memory_triage_demo.py --fullscreen
```

Verify the two modeled layouts without opening the GUI:

```powershell
python memory_triage_demo.py --self-test
```

Python 3.10 or newer is required. The visual uses Tkinter and other Python
standard-library modules; it has no third-party package requirements.

## Presentation controls

| Control | Action |
| --- | --- |
| **NEXT** or Right Arrow | Start/replay the next scene's scan |
| **RESTART** or Backspace | Return to the contiguous example |
| **EXIT** | Close the demo |
| F11 | Toggle fullscreen |
| Escape | Leave fullscreen |

Resize the window to suit the projector. The visual scales uniformly, keeps its
aspect ratio, and centers within the available space. A minimum window size
preserves legibility.

## Scene-by-scene walkthrough

1. **Contiguous:** The broker's six frames occupy one adjacent span. Watch the
   scan visit the process-owned frames and flag the injected, unbacked RWX page.
2. **Non-contiguous:** The same process's pages are scattered. Watch the
   page-map order jump between frames while still finding the injected page.
   The lower panel updates with the current frame/page and explains that free
   gaps are skipped.
3. **Why it works:** Compare the frame ranges and identical finding rule. The
   page-aware scan inspects mapped regions; it does not assume physical
   adjacency. The suspicious permission/backing combination is a triage
   signal, not a malware verdict.

The lower status panel is intentionally scene-aware: it changes from the
contiguous scan step, to the current non-contiguous page-map lookup, to the
cross-layout conclusion. During either animated scan, its frame and page detail
advances with the scan.

## Suggested presentation handoff

Use the demo immediately after introducing contiguous and non-contiguous
allocation. Keep the explanation brief and let the animation carry the detail:

1. Introduce the problem: a process's memory can be arranged differently in
   physical RAM.
2. Let the contiguous scan finish. Say: “First, the scan checks a contiguous
   process span and flags a page that is executable, writable, and not backed
   by a file.”
3. Advance to the non-contiguous scene. Say: “Now the same process pages are
   scattered. Following the page map lets the scan check them across gaps and
   find the same kind of anomaly.”
4. Advance to the comparison. Close with: “The placement changed; the finding
   rule did not. The page map tells the scan where to look.”
Start the window or toggle **F11** before presenting, pause briefly after each
scan completes, and keep the final comparison visible while transitioning back
to the presentation.

## Model and implementation reference

### Data model

- `Frame` is an immutable sample physical-memory frame.
  - `owner` identifies the sample process, kernel, or a free frame.
  - `page` labels the mapped process page.
  - `permissions` contains the displayed access flags.
  - `backing` is `IMAGE` for file-backed examples or `NONE` for the injected
    sample.
  - `suspicious` is true only for `RWX` + `NONE`; the UI presents this as a
    review candidate, not a definitive malware classification.
- `contiguous_layout()` returns the sample with broker frames 04–09 adjacent.
- `scattered_layout()` returns the same six broker pages at frames 01, 04, 06,
  08, 11, and 14.
- `CONTIGUOUS` and `SCATTERED` are the rendered layouts.
- `SCANNED_CONTIGUOUS` and `SCANNED_SCATTERED` are the ordered frame indices
  the animation visits for each layout.
- `FRAME_COUNT`, `WIDTH`, and `HEIGHT` define the model's physical-frame count
  and the logical canvas size. The window can scale independently of those
  coordinates.

### `RamLayoutDemo`

The `RamLayoutDemo` class owns the Tk window, canvas, scene state, scan
animation, drawing methods, and presentation controls.

- `draw()` redraws the current page and scales/centers the logical canvas.
- `draw_header()`, `draw_layout_scene()`, `draw_comparison_scene()`, and
  `draw_controls()` render the scene's main sections.
- `draw_frames()` renders frame ownership, mapping, permissions, and scan
  highlights. `draw_scan_detail()` updates the explanation below the frame map
  as frames are checked and after a finding is made.
- `start_scene_scan()` resets the page's scan. `scan_next_frame()` advances one
  mapped frame and schedules the next animation step.
- `next_scene()` and `restart()` navigate the three scenes.
- `on_resize()` and `redraw_after_resize()` debounce window resizing.
- `toggle_fullscreen()` and `leave_fullscreen()` control presentation mode.
- `on_click()` dispatches UI clicks; `exit_demo()` closes the app.
- `rect()`, `text()`, and `button()` are logical-coordinate canvas helpers.
- `contains()` tests a point against logical-coordinate button bounds.

### Entry points

- `self_test()` checks the scan's expected finding in both layouts.
- `main()` parses options and launches the GUI or self-test.