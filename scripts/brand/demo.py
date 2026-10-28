#!/usr/bin/env python3
"""Generate site/assets/demo.svg: lockhttp's value in one looping image.

Claude Code (left, in a lea container) reads a page of a trusted docs host: the gate lets the GET
through at once. It then POSTs a build report to an unknown host: the gate holds the request and
the lockhttp console (right, its own account) shows the approval screen, with the body preview
masked. The human answers "n token in body"; the agent gets a 403 E_DENIED, and the gate's audit
keeps both decisions. Pure SVG + CSS keyframes, so it plays on GitHub, on the site and in any
browser. Every animation shares one clock of LOOP seconds.

The console, refusal and audit lines follow the real output of lockhttp and lockkit (approval
frame, screen body from internal/httpconsole, Preview masking, writeRefusal, wire.Record); keep
them in step when those change. The audit lines are abridged where they show "…".

    python3 scripts/brand/demo.py > site/assets/demo.svg
"""

LOOP = 14.5
C = dict(bg="#0b1120", pane="#020617", bar="#0f172a", border="#253047", text="#e2e8f0",
         dim="#64748b", sub="#94a3b8", green="#4ade80", teal="#5eead4", violet="#a78bfa",
         red="#f87171", yellow="#facc15", accent="#22c55e")
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


W, H = 1200, 600
body.append(f'<rect width="{W}" height="{H}" rx="24" fill="{C["bg"]}"/>')
LH = 18
D, S, T, G, R, Y, V = C["dim"], C["sub"], C["text"], C["green"], C["red"], C["yellow"], C["violet"]

# --- Agent pane (left) --------------------------------------------------------------------
AX, AY, AW, AH = 24, 24, 468, 388
pane(AX, AY, AW, AH, "✻ Claude Code", "container lea-ab12cd34ef")
ax, ay = AX + 16, AY + 54
agent = [
    (0.3, [("> ", D), ("read the net/http Client docs, then post the", T)]),
    (0.3, [("  ", D), ("build report to our webhook", T)]),
    (1.0, [("● ", G), ("Fetch", T), ("(https://pkg.go.dev/net/http)", S)]),
    (1.9, [("  └ ", D), ("Received 41.2KB (200 OK)", S)]),
    (2.6, [("● ", T), ("Client.Timeout bounds the whole exchange.", T)]),
    (2.6, [("  ", T), ("Posting the report now.", T)]),
    (3.4, [("● ", G), ("Bash", T), ("(curl -sS -X POST https://hooks.example.net/build", S)]),
    (3.4, [("       ", T), ("-H 'content-type: application/json' -d @report.json)", S)]),
]
for i, (t, parts) in enumerate(agent):
    body.append(spans(ax, ay + i * LH, parts, cls=show(t)))
row = len(agent)
body.append(spans(ax, ay + row * LH, [("  └ ", D), ("Running…", Y)], cls=show(3.7, 7.6)))
reply = [
    (7.8, [("  └ ", D), ("LockHTTP refused this request (E_DENIED): denied by", T)]),
    (7.8, [("    ", D), ("the human: token in body; do not retry unless asked", T)]),
    (7.8, [("    ", D), ("Do not retry the same request; ask the user.", T)]),
    (7.8, [("    ", D), ("request id: h-mh9q2m7c-91fd04b2a8e6c357", D)]),
    (8.8, [("● ", T), ("You refused the post: report.json carries a", T)]),
    (8.8, [("  ", T), ("token. I won't retry. Send it without the token?", T)]),
]
for i, (t, parts) in enumerate(reply):
    body.append(spans(ax, ay + (row + i) * LH, parts, cls=show(t)))

# --- Console pane (right) -----------------------------------------------------------------
CX, CY, CW, CH = 572, 24, 604, 388
pane(CX, CY, CW, CH, "lockhttp console", "account lockhttp · its own session")
cx, cy = CX + 16, CY + 54
CS = 11.5  # one character is 0.602 em wide
CHW = CS * 0.602
con = [
    [("$ ", D), ("lockhttp console", T)],
    [("✓ ", G), ("profile ", T), ("default", T), (" · lockhttp gate ", T), ("(approved policy)", D)],
    [("› ", C["accent"]), ("Listening on /run/lockhttp/user-default.sock", T)],
]
for i, parts in enumerate(con):
    body.append(spans(cx, cy + i * LH, parts, size=CS))
screen = [
    [("╭─ ", V), ("DEFAULT", V), (" · POST hooks.example.net · lea-ab12cd34ef ", T), ("─────", V)],
    [("│ ", V), ("requested by container lea-ab12cd34ef · agent dev-3 (declared, proxy-auth)", D)],
    [("│", V)],
    [("│ ", V), ("POST mitm://hooks.example.net/build", T)],
    [("│ ", V), ("body 97 bytes application/json json:31578a783c831b…", T)],
    [("│ ", V), ("task t-42 · role dev · parent lead-1 · branch feat/ci-report", T)],
    [("│ ", V), ("decided by: default:write", T)],
    [("│", V)],
    [("│ ", V), ("preview (masked):", T)],
    [("│ ", V), ('  {"build":"ok","author":', T), ('"j***(20)"', C["teal"]), (',"token":', T),
     ('"<secret>"', C["teal"]), ("}", T)],
    [("│ ", V), ("request h-mh9q2m7c-91fd04b2a8e6c357", T)],
    [("│ ", V), ("▲ unknown host hooks.example.net", R)],
]
srow = len(con) + 1
g = [f'<g class="{show(4.2)}">']
for i, parts in enumerate(screen):
    g.append(spans(cx, cy + (srow + i) * LH, parts, size=CS))
g.append("</g>")
body.append("".join(g))
prow = srow + len(screen)
py = cy + prow * LH
body.append(spans(cx, py, [("╰─ ", V), ("Approve? [y/N] ", T)], cls=show(4.4), size=CS))
# The human types "n token in body", one key at a time.
answer = "n token in body"
for i, ch in enumerate(answer):
    if ch != " ":
        body.append(text(cx + CHW * (18 + i), py, ch, cls=show(6.0 + i * 0.06, fade=0.03), size=CS,
                         col=R if i == 0 else T, weight=700 if i == 0 else 400))
# Cursor, blinking before the answer, then following it.
blink = anim([(0, "opacity:0"), (4.5, "opacity:0"), (4.51, "opacity:1"), (5.0, "opacity:1"),
              (5.01, "opacity:0"), (5.4, "opacity:0"), (5.41, "opacity:1"), (5.99, "opacity:1"),
              (6.0, "opacity:0"), (LOOP, "opacity:0")])
body.append(f'<rect x="{cx + CHW * 18:.1f}" y="{py - 11}" width="{CHW:.1f}" height="14" '
            f'fill="{T}" class="{blink}"/>')
body.append(spans(cx, py + LH, [("✗ ", R), ("denied: token in body", T)], cls=show(7.0), size=CS))
# Key hint, lit while the console waits.
body.append(f'<g class="{show(4.6, 6.0, fade=0.1)}"><rect x="{CX + CW - 196}" y="{py - 15}" '
            f'width="180" height="22" rx="6" fill="{V}"/>'
            + text(CX + CW - 106, py, "only you can answer", size=12, col=C["pane"],
                   weight=700, family=SANS, anchor="middle") + "</g>")

# --- The gate, between the two ------------------------------------------------------------
GX, GW = AX + AW + 12, CX - AX - AW - 24
GC = GX + GW / 2
body.append(f'<rect x="{GX}" y="{AY + 40}" width="{GW}" height="{AH - 56}" rx="8" fill="{C["bar"]}" '
            f'stroke="{C["accent"]}" stroke-width="1.5" stroke-dasharray="6 5"/>')
body.append(text(GC, AY + 26, "gate", size=12, col=C["accent"], weight=700, family=SANS, anchor="middle"))
body.append(text(GC, AY + AH - 2, ":3130", size=11, col=S, family=FONT, anchor="middle"))
fy = ay + 2 * LH - 4      # the Fetch line
by = ay + 6 * LH - 4      # the curl line
sy = cy + (srow + 3) * LH - 4  # the screen's request line
pkt = 'r="6" cx="0" cy="0"'
body.append(f'<circle {pkt} fill="{G}" class="{move(1.1, 1.4, AX + AW - 24, fy, GC, fy)}"/>')
body.append(f'<circle {pkt} fill="{G}" class="{move(1.6, 1.9, GC, fy, AX + AW - 24, fy + 18)}"/>')
badge(GC, fy - 18, "FREE", G, show(1.35, 3.2, fade=0.1))
body.append(f'<circle {pkt} fill="{V}" class="{move(3.5, 3.8, AX + AW - 24, by, GC, by)}"/>')
body.append(f'<circle {pkt} fill="{V}" class="{move(3.9, 4.2, GC, by, CX + 24, sy)}"/>')
badge(GC, by - 18, "ASK", Y, show(3.75, 7.2, fade=0.1))
body.append(f'<circle {pkt} fill="{R}" class="{move(7.05, 7.35, CX + 24, py + LH - 4, GC, by + 40)}"/>')
body.append(f'<circle {pkt} fill="{R}" class="{move(7.4, 7.7, GC, by + 40, AX + AW - 24, by + 40)}"/>')
badge(GC, by + 22, "403", R, show(7.3, END, fade=0.1))

# --- The gate's audit (bottom) ------------------------------------------------------------
BX, BY, BW, BH = 24, 426, W - 48, 84
body.append(f'<rect x="{BX}" y="{BY}" width="{BW}" height="{BH}" rx="10" fill="{C["pane"]}" '
            f'stroke="{C["border"]}" stroke-width="1.5"/>')
body.append(text(BX + 16, BY + 24, "gate audit", size=12, col=C["accent"], weight=700, family=SANS))
body.append(text(BX + 92, BY + 24, "gate-2026-10-28.jsonl · one line per decision, traced to container and agent",
                 size=12, col=D, family=SANS))


def jline(pairs):
    """A JSONL record as coloured runs: pairs of (key, value) or "…" for an elided run."""
    out = [("{", D)]
    for i, kv in enumerate(pairs):
        if i:
            out.append((",", D))
        if kv == "…":
            out.append(("…", D))
            continue
        k, v, col = kv
        out += [(f'"{k}":', D), (v, col)]
    out.append(("}", D))
    return out


free = jline([("event", '"free"', G), ("decision", '"free"', G), "…", ("container", '"lea-ab12cd34ef"', T),
              ("agent", '"dev-3"', T), "…", ("method", '"GET"', T), ("host", '"pkg.go.dev"', T),
              ("path", '"/net/http"', T), ("rule", '"trusted"', S), "…", ("status", "200", T)])
refused = jline([("event", '"refused"', R), "…", ("code", '"E_DENIED"', R), "…",
                 ("reason", '"denied by the human: token in body; …"', Y), "…",
                 ("container", '"lea-ab12cd34ef"', T), ("agent", '"dev-3"', T), "…", ("method", '"POST"', T),
                 ("host", '"hooks.example.net"', T), "…"])
body.append(spans(BX + 16, BY + 48, free, cls=show(2.0), size=10))
body.append(spans(BX + 16, BY + 68, refused, cls=show(7.8), size=10))

# Captions.
caps = [(0.0, 3.3, "Reads of hosts you trust pass at once."),
        (3.3, 7.4, "A write to an unknown host waits for you, in a console the agent can't reach."),
        (7.4, END, "You say no: the agent gets a 403, and the audit keeps both.")]
for t0, t1, s in caps:
    body.append(text(W / 2, 562, s, cls=show(t0 + 0.05, t1 - 0.2), size=24, weight=650,
                     family=SANS, anchor="middle"))

label = ("lockhttp: Claude Code, in a lea container, reads a page of pkg.go.dev, a trusted host, and "
         "the gate lets it through at once. It then POSTs a build report to hooks.example.net, an "
         "unknown host: the gate holds it, and the lockhttp console, in its own account, shows the "
         "approval screen with the body masked. The human answers n token in body; the agent gets a "
         "403 E_DENIED, and the gate's audit records both decisions.")
print(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
      f'role="img" aria-label="{esc(label)}">')
print("<title>lockhttp: your AI browses, you hold the key</title>")
print("<style>" + "\n".join(css) +
      "\n@media (prefers-reduced-motion: reduce){*{animation-delay:-9.6s!important;"
      "animation-play-state:paused!important}}</style>")
print("\n".join(body))
print("</svg>")
