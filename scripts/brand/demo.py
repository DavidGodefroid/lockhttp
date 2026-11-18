#!/usr/bin/env python3
"""Generate site/assets/demo.svg: lockhttp's value in one looping image.

An agent (left, Claude Code in a lea container) reads a page of a trusted host: the gate lets the
GET through at once. It then POSTs a build report to an unknown host: the gate holds the request
and asks lockhub, and the question shows in `lox run` (right, the human's own terminal, outside
lea). The human presses d to read the whole masked screen, then n; the agent gets a 403 E_DENIED,
and the gate's audit keeps both decisions. Pure SVG + CSS keyframes, so it plays on GitHub, on
the site and in any browser. Every animation shares one clock of LOOP seconds.

No output on screen is written here: it is read from scripts/brand/demo-capture/, a capture of
the scenario run through the code itself.

  gate.txt         the two curl commands run through the gate (internal/gate) with lea's
                   sources.json, their output as curl printed it, and the gate's audit records
  lox-run-*.ans    the frames lockhub's `lox run` (internal/loxrun) drew for the gate's ticket,
                   with their colours: idle, the question, the question after d, after n

What is typed here is the scenario's input (the prompt, the two commands), Claude Code's frame
around a command and its output, the pane titles, the badges and the captions. The audit lines
are the captured records with fields left out where they show "…".

    python3 scripts/brand/demo.py > site/assets/demo.svg
"""

import json
import pathlib
import re

CAPTURE = pathlib.Path(__file__).parent / "demo-capture"

LOOP = 16.0
C = dict(bg="#0b1120", pane="#020617", bar="#0f172a", border="#253047", text="#e2e8f0",
         dim="#64748b", sub="#94a3b8", green="#4ade80", teal="#5eead4", violet="#a78bfa",
         red="#f87171", yellow="#facc15", cyan="#22d3ee", accent="#22c55e")
FONT = "'JetBrains Mono','SF Mono',Menlo,Consolas,'DejaVu Sans Mono',monospace"
SANS = "Inter,-apple-system,'Segoe UI',system-ui,Helvetica,Arial,'DejaVu Sans',sans-serif"

css, body = [], []
n = 0


def p(t):
    return f"{t / LOOP * 100:.2f}%"


def anim(frames):
    """Register keyframes [(time_s, 'css decls'), ...] and return a class name."""
    global n
    n += 1
    name = f"k{n}"
    rules = " ".join(f"{p(t)}{{{d}}}" for t, d in frames)
    css.append(f"@keyframes {name}{{{rules}}}")
    css.append(f".{name}{{animation:{name} {LOOP}s linear infinite}}")
    return name


END = LOOP - 0.6


def show(t_in, t_out=END, fade=0.2):
    """Opacity window: hidden, visible from t_in to t_out."""
    return anim([(0, "opacity:0"), (t_in, "opacity:0"), (t_in + fade, "opacity:1"),
                 (t_out, "opacity:1"), (t_out + fade, "opacity:0"), (LOOP, "opacity:0")])


def move(t0, t1, x0, y0, x1, y1):
    return anim([(0, f"transform:translate({x0}px,{y0}px);opacity:0"),
                 (t0, f"transform:translate({x0}px,{y0}px);opacity:0"),
                 (t0 + 0.05, f"transform:translate({x0}px,{y0}px);opacity:1"),
                 (t1, f"transform:translate({x1}px,{y1}px);opacity:1"),
                 (t1 + 0.15, f"transform:translate({x1}px,{y1}px);opacity:0"),
                 (LOOP, f"transform:translate({x1}px,{y1}px);opacity:0")])


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def text(x, y, s, cls="", size=11.5, col=C["text"], weight=400, family=FONT, anchor="start"):
    c = f' class="{cls}"' if cls else ""
    return (f'<text x="{x:.1f}" y="{y}"{c} font-family="{family}" font-size="{size}" '
            f'fill="{col}" font-weight="{weight}" text-anchor="{anchor}" xml:space="preserve">{esc(s)}</text>')


def spans(x, y, parts, cls="", size=11.5):
    """One line of coloured runs [(text, colour), ...]."""
    c = f' class="{cls}"' if cls else ""
    runs = "".join(f'<tspan fill="{col}">{esc(s)}</tspan>' for s, col in parts)
    return (f'<text x="{x}" y="{y}"{c} font-family="{FONT}" font-size="{size}" '
            f'xml:space="preserve">{runs}</text>')


def pane(x, y, w, h, title, account):
    body.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{C["pane"]}" '
                f'stroke="{C["border"]}" stroke-width="1.5"/>')
    body.append(f'<path d="M{x} {y + 12} a12 12 0 0 1 12 -12 h{w - 24} a12 12 0 0 1 12 12 v18 h-{w} z" '
                f'fill="{C["bar"]}"/>')
    for i, col in enumerate(("#f87171", "#facc15", "#4ade80")):
        body.append(f'<circle cx="{x + 18 + i * 16}" cy="{y + 15}" r="5" fill="{col}" fill-opacity=".7"/>')
    body.append(text(x + 70, y + 20, title, size=12, col=C["sub"], family=SANS, weight=600))
    body.append(text(x + w - 14, y + 20, account, size=12, col=C["dim"], family=SANS, anchor="end"))


def badge(xc, y, label, col, cls):
    w = len(label) * 7.6 + 16
    body.append(f'<g class="{cls}"><rect x="{xc - w / 2:.1f}" y="{y - 14}" width="{w:.1f}" height="20" '
                f'rx="5" fill="{col}"/>' + text(xc, y, label, size=11.5, col=C["pane"], weight=700,
                                                 family=FONT, anchor="middle") + "</g>")


# --- The capture --------------------------------------------------------------------------

def read_gate():
    """gate.txt: the output of each curl, and the audit records."""
    raw = (CAPTURE / "gate.txt").read_text()
    runs, audit = raw.split("== AUDIT\n")
    outs = []
    for block in runs.split("$ curl ")[1:]:
        out = block[:block.index("[exit: ")]
        # The command's own echo ends at its URL or its last argument.
        marker = "https://pkg.go.dev/net/http\n" if "pkg.go.dev" in out else "-d @report.json\n"
        outs.append(out[out.index(marker) + len(marker):].rstrip("\n").split("\n"))
    return outs, [json.loads(l) for l in audit.splitlines() if l.strip()]


SGR = re.compile(r"\x1b\[([0-9;]*)m")
FG = {"30": C["pane"], "31": C["red"], "32": C["green"], "33": C["yellow"], "36": C["cyan"]}
BG = {"42": C["green"]}


def read_frame(name):
    """A frame of lox run as rows of runs (col, text, colour, bold, italic, background)."""
    rows = []
    for raw in (CAPTURE / f"lox-run-{name}.ans").read_text().split("\n"):
        runs, col, pos = [], 0, 0
        fg, bold, italic, bg, dim = C["text"], False, False, None, False

        def emit(s):
            nonlocal col
            if s:
                colour = fg if not dim or fg != C["text"] else C["sub"]
                runs.append((col, s, colour, bold, italic, bg))
                col += len(s)

        for m in SGR.finditer(raw):
            emit(raw[pos:m.start()])
            pos = m.end()
            for code in (m.group(1) or "0").split(";"):
                if code in ("0", ""):
                    fg, bold, italic, bg, dim = C["text"], False, False, None, False
                elif code == "1":
                    bold = True
                elif code == "2":
                    dim = True
                elif code == "3":
                    italic = True
                elif code in FG:
                    fg = FG[code]
                elif code in BG:
                    bg = BG[code]
                else:
                    raise SystemExit(f"demo.py: SGR {code} of lox-run-{name}.ans has no colour here")
        emit(raw[pos:])
        rows.append(runs)
    return rows


def draw_frame(rows, x, y, lh, size, cls):
    """Each run is placed at its own column and stretched to its width, so a glyph taken from
    a fallback font never shifts what follows it."""
    chw = size * 0.602
    out = [f'<g class="{cls}" font-family="{FONT}" font-size="{size}">']
    for r, runs in enumerate(rows):
        yy = y + r * lh
        for col, s, colour, bold, italic, bg in runs:
            if bg:
                out.append(f'<rect x="{x + col * chw:.1f}" y="{yy - size + 1:.1f}" width="{len(s) * chw:.1f}" '
                           f'height="{size + 3:.1f}" fill="{bg}"/>')
            lead = len(s) - len(s.lstrip(" "))
            t = s.strip(" ")
            if not t:
                continue
            attrs = f' font-weight="700"' if bold else ""
            attrs += ' font-style="italic"' if italic else ""
            out.append(f'<text x="{x + (col + lead) * chw:.1f}" y="{yy}" fill="{colour}"{attrs} '
                       f'textLength="{len(t) * chw:.1f}" lengthAdjust="spacingAndGlyphs" '
                       f'xml:space="preserve">{esc(t)}</text>')
    out.append("</g>")
    return "".join(out)


curl_out, audit = read_gate()
get_out, post_out = curl_out
free_rec = next(r for r in audit if r["event"] == "free")
denied_rec = next(r for r in audit if r["event"] == "denied")
container, agent_name = free_rec["container"], free_rec["agent"]

W, H = 1200, 680
body.append(f'<rect width="{W}" height="{H}" rx="24" fill="{C["bg"]}"/>')
LH = 18
D, S, T, G, R, Y, V = C["dim"], C["sub"], C["text"], C["green"], C["red"], C["yellow"], C["violet"]

# Timeline (seconds).
T_GET, T_GET_OUT = 1.0, 1.9
T_POST, T_ASK = 3.2, 4.0
T_DETAILS, T_DENY, T_REPLY = 6.0, 9.4, 10.2

# --- Agent pane (left) --------------------------------------------------------------------
AX, AY, AW, AH = 24, 24, 476, 468
pane(AX, AY, AW, AH, "✻ Claude Code", f"container {container}")
ax, ay = AX + 16, AY + 54
agent = [
    (0.3, [("> ", D), ("check that the net/http docs are up, then post the", T)]),
    (0.3, [("  ", D), ("build report to our webhook", T)]),
    (None, []),
    (T_GET, [("● ", G), ("Bash", T), ("(curl -sS -o /dev/null -w '%{http_code}\\n'", S)]),
    (T_GET, [("       ", T), ("https://pkg.go.dev/net/http)", S)]),
]
agent += [(T_GET_OUT, [("  └ " if i == 0 else "    ", D), (l, T)]) for i, l in enumerate(get_out)]
agent += [
    (None, []),
    (T_POST, [("● ", G), ("Bash", T), ("(curl -sS -X POST https://hooks.example.net/build", S)]),
    (T_POST, [("       ", T), ("-H 'content-type: application/json' -d @report.json)", S)]),
]
get_row = 3
post_row = len(agent) - 2
for i, (t, parts) in enumerate(agent):
    if parts:
        body.append(spans(ax, ay + i * LH, parts, cls=show(t)))
row = len(agent)
body.append(spans(ax, ay + row * LH, [("  └ ", D), ("Running…", Y)], cls=show(T_POST + 0.3, T_REPLY - 0.2)))


def wrap(s, width):
    """Wrap on spaces, as the agent's terminal does."""
    out, cur = [], ""
    for word in s.split(" "):
        if cur and len(cur) + 1 + len(word) > width:
            out.append(cur)
            cur = word
        else:
            cur = f"{cur} {word}" if cur else word
    return out + [cur]


reply = []
for l in post_out:
    reply += wrap(l, 60)
for i, l in enumerate(reply):
    colour = D if l.startswith("request id:") else T
    body.append(spans(ax, ay + (row + i) * LH, [("  └ " if i == 0 else "    ", D), (l, colour)],
                      cls=show(T_REPLY)))

# --- lox run pane (right) -----------------------------------------------------------------
CX, CY, CW, CH = 580, 24, 596, 468
pane(CX, CY, CW, CH, "lox run", "your terminal · outside lea")
CS, CLH = 11.5, 16
CHW = CS * 0.602
cx, cy = CX + 20, CY + 52
frames = [("idle", 0.0, T_ASK), ("question", T_ASK, T_DETAILS), ("details", T_DETAILS, T_DENY),
          ("denied", T_DENY, END)]
for name, t0, t1 in frames:
    rows = read_frame(name)
    if name == "idle":
        cls = anim([(0, "opacity:1"), (t1, "opacity:1"), (t1 + 0.1, "opacity:0"), (END + 0.5, "opacity:0"),
                    (LOOP, "opacity:1")])
    else:
        cls = show(t0, END if name == "denied" else t1, fade=0.1)
    body.append(draw_frame(rows, cx, cy, CLH, CS, cls))


def key_hint(t0, t1, label):
    """The key the human presses: lox run does not echo it."""
    w = 196
    xc = CX + CW / 2 - 10
    body.append(f'<g class="{show(t0, t1, fade=0.1)}"><rect x="{xc - w / 2}" y="{CY + 4}" '
                f'width="{w}" height="22" rx="6" fill="{V}"/>'
                + text(xc, CY + 19.5, label, size=12, col=C["pane"],
                       weight=700, family=SANS, anchor="middle") + "</g>")


key_hint(T_ASK + 0.9, T_DETAILS, "you press d: the whole screen")
key_hint(T_DETAILS + 2.2, T_DENY, "you press n: deny")

# --- The gate, between the two ------------------------------------------------------------
GX, GW = AX + AW + 12, CX - AX - AW - 24
GC = GX + GW / 2
body.append(f'<rect x="{GX}" y="{AY + 40}" width="{GW}" height="{AH - 56}" rx="8" fill="{C["bar"]}" '
            f'stroke="{C["accent"]}" stroke-width="1.5" stroke-dasharray="6 5"/>')
body.append(text(GC, AY + 26, "gate", size=12, col=C["accent"], weight=700, family=SANS, anchor="middle"))
fy = ay + get_row * LH - 4       # the GET's line
by = ay + post_row * LH - 4      # the POST's line
sy = cy + 4 * CLH - 4            # the question card's first row
pkt = 'r="6" cx="0" cy="0"'
body.append(f'<circle {pkt} fill="{G}" class="{move(T_GET + 0.1, T_GET + 0.4, AX + AW - 24, fy, GC, fy)}"/>')
body.append(f'<circle {pkt} fill="{G}" class="{move(T_GET + 0.6, T_GET + 0.9, GC, fy, AX + AW - 24, fy + 36)}"/>')
badge(GC, fy - 18, "FREE", G, show(T_GET + 0.35, T_POST, fade=0.1))
body.append(f'<circle {pkt} fill="{V}" class="{move(T_POST + 0.3, T_POST + 0.6, AX + AW - 24, by, GC, by)}"/>')
body.append(f'<circle {pkt} fill="{V}" class="{move(T_POST + 0.6, T_ASK, GC, by, CX + 24, sy)}"/>')
badge(GC, by - 18, "ASK", Y, show(T_POST + 0.55, T_DENY + 0.3, fade=0.1))
body.append(f'<circle {pkt} fill="{R}" class="{move(T_DENY + 0.1, T_DENY + 0.4, CX + 24, sy, GC, by + 40)}"/>')
body.append(f'<circle {pkt} fill="{R}" class="{move(T_DENY + 0.45, T_REPLY - 0.1, GC, by + 40, AX + AW - 24, by + 40)}"/>')
badge(GC, by + 22, "403", R, show(T_DENY + 0.4, END, fade=0.1))

# --- The gate's audit (bottom) ------------------------------------------------------------
BX, BY, BW, BH = 24, 506, W - 48, 84
body.append(f'<rect x="{BX}" y="{BY}" width="{BW}" height="{BH}" rx="10" fill="{C["pane"]}" '
            f'stroke="{C["border"]}" stroke-width="1.5"/>')
body.append(text(BX + 16, BY + 24, "gate audit", size=12, col=C["accent"], weight=700, family=SANS))
body.append(text(BX + 92, BY + 24, f"gate-{free_rec['ts'][:10]}.jsonl · one line per decision, traced to container and agent",
                 size=12, col=D, family=SANS))


def jline(rec, keys, colours):
    """A captured record as coloured runs, with "…" wherever fields are left out."""
    out, prev = [("{", D)], -1
    order = list(rec)
    for k in keys:
        i = order.index(k)
        if prev >= 0:
            out.append((",", D))
        if i != prev + 1:
            out.append(("…,", D) if prev >= 0 else ("…", D))
            if prev < 0:
                out.append((",", D))
        out += [(f'"{k}":', D), (json.dumps(rec[k], ensure_ascii=False, separators=(",", ":")), colours.get(k, T))]
        prev = i
    if prev != len(order) - 1:
        out.append((",…", D))
    out.append(("}", D))
    return out


free = jline(free_rec, ["event", "container", "agent", "method", "host", "path", "rule", "status"],
             {"event": G, "rule": S})
denied = jline(denied_rec, ["event", "reason", "approval", "facade", "container", "agent", "method", "host"],
               {"event": R, "reason": Y})
body.append(spans(BX + 16, BY + 48, free, cls=show(T_GET_OUT + 0.1), size=10))
body.append(spans(BX + 16, BY + 68, denied, cls=show(T_DENY + 0.4), size=10))

# Captions.
caps = [(0.0, T_POST, "Reads of hosts you trust pass at once."),
        (T_POST, T_DENY, "A write to an unknown host waits for you in lox run, which the agent can't reach."),
        (T_DENY, END, "You say no: the agent gets a 403, and the audit keeps both.")]
for t0, t1, s in caps:
    body.append(text(W / 2, 642, s, cls=show(t0 + 0.05, t1 - 0.2), size=24, weight=650,
                     family=SANS, anchor="middle"))

label = ("lockhttp: an agent (Claude Code, in a lea container) fetches a page of pkg.go.dev, a trusted "
         "host, and the gate lets the GET through at once. It then POSTs a build report to "
         "hooks.example.net, an unknown host: the gate holds it, and a question shows in lox run, in "
         "the human's own terminal. The human presses d to read the whole masked screen (the author's "
         "email shows as j***(23)), then n; the agent gets a 403 E_DENIED, denied on the hub, and the "
         "gate's audit records both decisions.")
print(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
      f'role="img" aria-label="{esc(label)}">')
print("<title>lockhttp: your agent browses, you hold the key</title>")
print("<style>" + "\n".join(css) +
      f"\n@media (prefers-reduced-motion: reduce){{*{{animation-delay:-{T_DETAILS + 1.5}s!important;"
      "animation-play-state:paused!important}}</style>")
print("\n".join(body))
print("</svg>")
