---
version: alpha
name: Monogatari-design-analysis
description: A design system interpretation of the Monogatari Series (Studio SHAFT) — an avant-garde, highly typographic, and starkly contrasting aesthetic. Built on pure Void Black, Blood Red, and Paper White, with a strict adherence to sharp geometry, split-second typographic flash cards, and character-coded accent colors. Typography heavily leans on traditional Japanese Mincho (Serif) fonts juxtaposed against modern environmental minimalism.

colors:
  primary-red: "#CC0000"
  primary-black: "#000000"
  primary-white: "#F8F8F8"
  paper-texture: "#F4F1EA"
  blueprint-blue: "#003366"
  caution-yellow: "#FFCC00"
  accent-senjougahara: "#7851A9"
  accent-hachikuji: "#FF69B4"
  accent-kanbaru: "#FFA500"
  accent-nadeko: "#2E8B57"
  accent-hanekawa: "#E0E0E0"
  accent-shinobu: "#FFD700"
  text-inverse: "#FFFFFF"
  text-main: "#111111"
  text-subdued: "#666666"

typography:
  flash-screen-xxl:
    fontFamily: "'Shippori Mincho', 'Noto Serif JP', serif"
    fontSize: 72px
    fontWeight: 700
    lineHeight: 1.0
    letterSpacing: 2.0px
    textTransform: "uppercase"
  flash-screen-xl:
    fontFamily: "'Shippori Mincho', 'Noto Serif JP', serif"
    fontSize: 56px
    fontWeight: 700
    lineHeight: 1.1
    letterSpacing: 1.5px
  display-serif:
    fontFamily: "'Shippori Mincho', 'Noto Serif JP', serif"
    fontSize: 32px
    fontWeight: 500
    lineHeight: 1.4
    letterSpacing: 1.0px
  body-gothic:
    fontFamily: "'Noto Sans JP', sans-serif"
    fontSize: 16px
    fontWeight: 400
    lineHeight: 1.6
    letterSpacing: 0.5px
  monologue-caption:
    fontFamily: "'Shippori Mincho', 'Noto Serif JP', serif"
    fontSize: 14px
    fontWeight: 400
    lineHeight: 1.8
    letterSpacing: 0.2px
  environmental-signage:
    fontFamily: "'Noto Sans JP', sans-serif"
    fontSize: 24px
    fontWeight: 900
    lineHeight: 1.0
    letterSpacing: -0.5px

rounded:
  none: 0px
  sharp: 0px
  circle: 9999px

spacing:
  micro: 2px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 32px
  xl: 64px
  cinematic: 128px
  void: 256px

components:
  flash-card-black:
    backgroundColor: "{colors.primary-black}"
    textColor: "{colors.text-inverse}"
    typography: "{typography.flash-screen-xxl}"
    rounded: "{rounded.none}"
    padding: 128px
    alignment: "center"
  flash-card-red:
    backgroundColor: "{colors.primary-red}"
    textColor: "{colors.primary-black}"
    typography: "{typography.flash-screen-xl}"
    rounded: "{rounded.none}"
    padding: 64px
    alignment: "center"
  dialogue-bar:
    backgroundColor: "{colors.primary-black}"
    textColor: "{colors.text-inverse}"
    typography: "{typography.body-gothic}"
    rounded: "{rounded.none}"
    padding: 16px 32px
    borderLeft: "8px solid {colors.primary-red}"
  character-tag-senjougahara:
    backgroundColor: "{colors.accent-senjougahara}"
    textColor: "{colors.text-inverse}"
    typography: "{typography.monologue-caption}"
    rounded: "{rounded.none}"
    padding: 4px 12px
  cinematic-letterbox:
    backgroundColor: "transparent"
    borderTop: "64px solid {colors.primary-black}"
    borderBottom: "64px solid {colors.primary-black}"
    padding: 0
---

## Overview

The Monogatari Series design language (pioneered by Studio SHAFT) is an exercise in extreme avant-garde minimalism, typographic aggression, and high-contrast geometry. It rejects standard UI paradigms in favor of a cinematic, theatrical experience. The interface does not guide the user gently; it flashes information at them, relies on stark architectural grids, and uses pure color as a narrative device.

The aesthetic is built on three pillars: **Void Black** (`{colors.primary-black}`), **Blood Red** (`{colors.primary-red}`), and **Paper White** (`{colors.paper-texture}`). These are punctuated by strictly assigned character accent colors.

Typography is the absolute core of the design [cite: 1]. Heavy traditional Mincho (Serif) fonts are used for internal monologues and rapid-fire "Flash Screens," creating a jarring juxtaposition against hyper-modern, almost sterile, geometric environments.

**Key Characteristics:**
- **Typographic Flash Screens:** Split-second, full-screen cards (Black/White, Red/Black) containing a single word or sentence.
- **Sharp Geometry:** Absolutely zero border-radius (`{rounded.none}`). Elements are perfect rectangles or perfectly abstract circles [cite: 1].
- **Cinematic Framing:** Heavy use of letterboxing (black bars) and extreme asymmetrical alignments.
- **Character Color Coding:** Subdued environments that suddenly highlight in a specific character's hex code (e.g., Purple for Senjougahara).
- **Environmental Signage:** Text incorporated directly into the background geometry (traffic signs, construction barriers) as structural UI elements.

## Colors

### Core Palette
- **Primary Black (Void)** (`{colors.primary-black}` — `#000000`): The default state. Used for flash screen backgrounds, letterboxing, and text on white [cite: 1].
- **Primary Red (Blood)** (`{colors.primary-red}` — `#CC0000`): The primary alert and highlight color. Represents danger, vampires, and critical narrative shifts [cite: 1].
- **Primary White** (`{colors.primary-white}` — `#F8F8F8`): High-contrast foreground element against black.
- **Paper Texture** (`{colors.paper-texture}` — `#F4F1EA`): A slightly warm off-white, representing the pages of a novel, used as a background canvas to reduce eye strain compared to pure white.

### Environmental
- **Blueprint Blue** (`{colors.blueprint-blue}` — `#003366`): Used for architectural backgrounds, grids, and wireframe representations of spaces.
- **Caution Yellow** (`{colors.caution-yellow}` — `#FFCC00`): Hazard tapes, construction signs, warnings.

### Character Accents
Used strictly for character-specific elements (tags, quotes, thematic sections):
- **Senjougahara Purple:** `#7851A9` (Crab / Weightless)
- **Hachikuji Pink:** `#FF69B4` (Snail / Lost)
- **Kanbaru Orange:** `#FFA500` (Monkey / Athletic)
- **Nadeko Green:** `#2E8B57` (Snake / Coil)
- **Hanekawa Silver:** `#E0E0E0` (Cat / Illusion)
- **Shinobu Gold:** `#FFD700` (Vampire / Ancient)

## Typography

### Font Family
The system relies on a jarring mix of classic and modern [cite: 1].
- **Primary (Narrative/Flash):** `Shippori Mincho` or `Noto Serif JP`. Represents the light novel origins.
- **Secondary (UI/Environmental):** `Noto Sans JP`. Used for rigid signage and modern interface elements.

### Hierarchy

| Token | Size | Weight | Line Height | Use |
|---|---|---|---|---|
| `{typography.flash-screen-xxl}` | 72px | 700 | 1.0 | Full-screen single word/kanji |
| `{typography.flash-screen-xl}` | 56px | 700 | 1.1 | Full-screen short sentence |
| `{typography.display-serif}` | 32px | 500 | 1.4 | Chapter titles, major headings |
| `{typography.body-gothic}` | 16px | 400 | 1.6 | Standard UI reading text |
| `{typography.monologue-caption}` | 14px | 400 | 1.8 | Subtitles, internal thoughts |
| `{typography.environmental-signage}` | 24px | 900 | 1.0 | Heavy sans-serif background text |

### Principles
- **Maximum Contrast:** Text must aggressively stand out. White on pure black, or black on pure red.
- **Vertical Rhythm (Tategaki):** Where possible, utilize vertical text alignment for display typography to emulate Japanese light novels.
- **Flash over Scroll:** Instead of scrolling a long paragraph, break it into 4-5 "Flash Screens" that sequence rapidly.

## Layout

### Spacing System
Spacing in this system relies on the concept of *Ma* (negative space) pushed to its absolute limit [cite: 1].
- Elements are either violently close to each other or separated by vast, empty voids (`{spacing.void}` 256px).
- Grid lines are explicitly drawn, not just implied.

### Grid & Container
- The frame is treated like a camera lens.
- **Letterboxing:** Use heavy top/bottom black borders (`{components.cinematic-letterbox}`) to force a 2.35:1 aspect ratio on standard screens.
- **Asymmetry:** Perfectly centered flash screens contrast with heavily left/right-aligned structural elements.

## Elevation & Depth

| Level | Treatment | Use |
|---|---|---|
| 0 | Flat | 90% of the UI. Completely flat, no shadows. |
| 1 | Hard Offset | `box-shadow: 8px 8px 0px 0px #000` - Retro/print style offset. |
| 2 | Parallax Layering | Foreground elements move at 3x the speed of architectural backgrounds. |

### Depth Philosophy
There are no drop shadows or soft blurs [cite: 1]. Depth is achieved purely through **parallax layering** and **hard cut-outs** (like collage paper).

## Shapes

### Border Radius Scale
- Everything is 0px [cite: 1]. The aesthetic is razor-sharp.
- The only exception is perfect circles (`9999px`) used for abstract visual motifs (like a flashing eye or traffic light).

## Components

### Flash Screens
**`flash-card-black`**
- The iconic Monogatari screen. Pure black background, bold white Mincho text, perfectly centered. Used to transition states or deliver a micro-interaction message (e.g., "Loading...", "Error").

**`flash-card-red`**
- The aggressive alternative. Pure red background, black text. Used for destructive actions or critical alerts.

### Structural
**`dialogue-bar`**
- A sharp black rectangle sitting at the bottom of the screen (resembling a subtitle bar).
- Features an 8px thick left border using a character's accent color (or pure red) to indicate who is "speaking" or what module is active.

**`cinematic-letterbox`**
- Static 64px pure black borders clamped to the top and bottom of the viewport, crushing the UI into a cinematic aspect ratio.

## Do's and Don'ts

### Do
- Use stark, unyielding colors (Pure Black, Pure White, Blood Red).
- Emphasize typography over iconography. Words *are* the UI.
- Implement split-second full-screen typographic takeovers for state changes.
- Keep all corners mathematically sharp (0px radius) [cite: 1].
- Incorporate structural grids and blueprint-like lines into the background canvas.

### Don't
- Don't use soft drop shadows, gradients, or blurs (unless representing a highly specific abstract hallucination) [cite: 1].
- Don't use rounded corners. It softens the aggressive architectural feel [cite: 1].
- Don't overcrowd the screen. Emphasize the void (negative space).
- Don't use standard generic blue for primary buttons. Use Black, Red, or a Character Accent.

## Motion Behavior
- **Hard Cuts over Easing:** Do not use soft easing curves (like ease-in-out). Elements should still enter and exit the screen linearly and immediately (0ms transition) to maintain the jarring, mechanical feel. The difference is in the *hold*, not the movement.
- **Sustained Blink Cuts:** UI elements pop in instantly like a film splice cut, but they must remain anchored on screen for a **minimum dwell time** (e.g., 1200ms to 2500ms, depending on word count) before cutting out abruptly. 
- **Anchored Typography Flashing:** Text can "flash" into existence (e.g., a 50ms pure red state that instantly snaps to white text on black), but instead of disappearing, it resolves into a static, readable state. Large blocks of narrative text should strictly rely on user interaction (scroll or click) to advance, rather than auto-flashing.
- **Accessibility Minimums:** Any critical "Flash Screen" meant to convey state changes (like "Loading", "Error", or "Success") must remain visible for at least 1500ms, ensuring users with different reading speeds can process the event.
- **No vertical text:** Text should not be placed vertically
