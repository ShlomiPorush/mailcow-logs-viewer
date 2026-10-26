"""
HTML layout for every email the app sends, in the v3 design language.

Email clients ignore stylesheets, CSS variables and grid, so the blocks are
tables with inline styles. The colours are the light theme of
frontend/assets/css/ui.css; a <style> block switches to the dark theme in the
clients that honour prefers-color-scheme (Apple Mail, iOS, Outlook for Mac),
and corrects it for the Outlook apps and Outlook.com (see _DARK_CSS).

Outlook for Windows draws email with Word, which ignores padding and margins
outside table cells, rounded corners, max-width and font fallbacks. So every
gap is cell padding or a spacer row, divider lines are 1px rows, and a block
never relies on margins.

Every value passed to a block is escaped. Only the output of another block
(a Safe string) is inserted as markup, so callers never escape by hand:

    html = render(
        title='2 hosts are on a blacklist',
        topic='Blacklist', tone='fail',
        intro='Mail from these hosts may be rejected.',
        blocks=[panel('Hosts', table(...))],
    )
"""
import functools
import re
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Iterable, Optional, Sequence, Tuple, Union

from .. import app_time


class Safe(str):
    """Markup produced by this module; inserted without escaping."""


def _attr(value) -> str:
    """Escape for an attribute or a place that takes no markup."""
    if isinstance(value, Safe):
        return value
    return escape('' if value is None else str(value), quote=True)


# Runs of the characters an address is made of. The text comes from inbound
# mail (DMARC subjects) among others, so the scan must stay linear: one
# character class, no nested or overlapping quantifiers; whether a run is an
# address is decided by plain string checks.
_ADDRESS_RUN = re.compile(r'[A-Za-z0-9._%+@-]+')
_DOMAIN_CHARS = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-')


def _is_address(text: str) -> bool:
    local, at, domain = text.partition('@')
    if not at or not local or '@' in domain:
        return False
    labels = domain.split('.')
    return len(labels) >= 2 and all(label and set(label) <= _DOMAIN_CHARS for label in labels)


def _e(value, cls: str = 'm-ink') -> str:
    """Escape visible text whose colour class is cls. Gmail and Outlook turn
    every address into a blue link of their own, and Outlook ignores
    color:inherit, so an address becomes a link of ours in the text colour."""
    if isinstance(value, Safe):
        return value
    color = _CLASS_COLORS.get(cls, INK)

    def link(match):
        run = match.group(0)
        address = run.rstrip('.')  # the full stop of a sentence is not part of it
        if not _is_address(address):
            return run
        return (f'<a href="mailto:{address}" class="{cls}" style="color:{color};text-decoration:none;">'
                f'{address}</a>{run[len(address):]}')

    return _ADDRESS_RUN.sub(link, _attr(value))


def local_now() -> datetime:
    """Now, in the app's time zone, like the dates in the app."""
    return app_time.local_now()


def format_date(when: datetime, time: bool = False, zone: bool = True) -> str:
    """The date in the app's time zone, written as Settings > Application > Time
    says (DD/MM/YYYY when that follows the browser). With the time, the zone
    follows it (13:00 CET) unless zone is False. A naive value is a stored
    one, so it is UTC."""
    local = app_time.to_local(when)
    text = app_time.format_day(local.date())
    if not time:
        return text
    text = f"{text} {app_time.format_clock(local.hour, local.minute)}"
    return f"{text} {app_time.zone_label(local)}" if zone else text


def format_time(when: datetime, zone: bool = True) -> str:
    """The time of day in the app's time zone, as format_date writes it
    (13:00 CET), without the date."""
    local = app_time.to_local(when)
    text = app_time.format_clock(local.hour, local.minute)
    return f"{text} {app_time.zone_label(local)}" if zone else text


def _lines(value, cls: str = 'm-ink') -> str:
    """Escape, then keep line breaks."""
    if isinstance(value, Safe):
        return value
    return _e(value, cls).replace('\n', '<br>')


FONT = "Onest, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
MONO = "'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

# ui.css light theme
BG = '#FFFFFF'
PANEL = '#F4F6F5'
INK = '#111814'
MUTED = '#5E6863'
LINE = '#E3E7E5'

# Tone colour and its tag/banner tint (the colour at 13-15% over white, as
# color-mix() gives in the app; email clients cannot mix colours)
TONES = {
    'ok': ('#12803F', '#E0F0E6'),
    'warn': ('#9A6200', '#F2EAD9'),
    'fail': ('#C42B1C', '#F8E0DE'),
    'info': ('#1F5FBF', '#E0E9F6'),
    'muted': ('#5E6863', '#ECEEED'),
}

_CLASS_COLORS = {'m-ink': INK, 'm-muted': MUTED, **{f'm-{t}': c for t, (c, _) in TONES.items()}}

# Bars of a chart: a neutral grey (no tint, so the Outlook apps keep it), and
# the fail colour for the bars that hold what the email is about
BAR = '#C4C4C4'
BAR_HI = TONES['fail'][0]

# Outlook for Android in dark mode (measured 2026-10-26) applies the dark
# theme, then recolours it again: the tinted backgrounds, dark or light, all
# came out as mid greys close to each other, so the email turned flat grey.
# Neutral greys kept their place (dark ones as they are, light ones inverted,
# white became the app's own background). Outlook marks recoloured elements
# with data-ogsb, so under that mark the email gets white and neutral greys.
# A rule on the marked element itself loses to the colour Outlook writes
# inline, so the rules match descendants only. The bars of a chart are a
# neutral grey for the same reason; its highlighted bars get their red there
# too, so Outlook cannot turn them into one more grey bar.
#
# Outlook and Gmail also turn dates into links of their own; a link in the
# email takes the colour of its text instead (link() keeps its underline).
_DARK_CSS = """
:root { color-scheme: light dark; supported-color-schemes: light dark; }
@media (prefers-color-scheme: dark) {
  .m-bg { background-color: #0E1110 !important; }
  .m-panel { background-color: #171B19 !important; }
  .m-ink { color: #F2F5F3 !important; }
  .m-muted { color: #97A29C !important; }
  .m-line { border-color: #262C29 !important; }
  .m-rule { background-color: #262C29 !important; }
  .m-mark { background-color: #F2F5F3 !important; }
  .m-mark i { background-color: #0E1110 !important; }
  .m-ok { color: #3FCF7F !important; } .m-ok-bg { background-color: #1A3325 !important; }
  .m-warn { color: #F0B03F !important; } .m-warn-bg { background-color: #3A2F1A !important; }
  .m-fail { color: #FF6B61 !important; } .m-fail-bg { background-color: #3D2220 !important; }
  .m-info { color: #7DB3FF !important; } .m-info-bg { background-color: #1E2C40 !important; }
  .m-muted-bg { background-color: #232826 !important; }
  .m-bar { background-color: #4A4A4A !important; }
  .m-bar-hi { background-color: #FF6B61 !important; }
}
[data-ogsb] .m-bg { background-color: #FFFFFF !important; }
[data-ogsb] .m-panel { background-color: #202020 !important; }
[data-ogsb] .m-line { border-color: #333333 !important; }
[data-ogsb] .m-rule { background-color: #333333 !important; }
[data-ogsb] .m-muted-bg { background-color: #333333 !important; }
[data-ogsb] .m-bar { background-color: #555555 !important; }
[data-ogsb] .m-bar-hi { background-color: #FF6B61 !important; }
.m-bg a { color: inherit !important; text-decoration: none !important; }
@media (max-width: 620px) {
  .m-wrap { padding: 24px 16px !important; }
  .m-h1 { font-size: 26px !important; }
  .m-stat { padding: 9px 10px !important; }
  .m-stat-v { font-size: 20px !important; }
  .m-cell { padding-left: 10px !important; padding-right: 10px !important; }
}
"""

# Word knows only bold and normal, and takes the first font of a list even
# when it is not installed (then it shows Times New Roman).
_MSO_CSS = """<!--[if mso]><style>
v\\:* { behavior: url(#default#VML); display: inline-block; }
body, table, td, th, p, a, span, h1, div { font-family: 'Segoe UI', Arial, sans-serif !important; }
.m-mono { font-family: Consolas, 'Courier New', monospace !important; }
.m-b { font-weight: bold !important; }
</style><![endif]-->"""

# Outlook for Windows draws no rounded corners. Panels, banners and cards
# stay square there: a VML shape that grows with its content does not push
# the next block down in Outlook, so blocks overlap. Only the topic tag,
# which has a fixed size, gets a rounded VML shape.

_TABLE = 'role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"'


def _tone(tone: Optional[str]) -> Tuple[str, str]:
    return TONES.get(tone or 'muted', TONES['muted'])


def _rule(colspan: int = 1) -> str:
    """A 1px divider row; Word draws cell borders unevenly."""
    return (f'<tr><td class="m-rule" colspan="{colspan}" height="1" style="height:1px;font-size:1px;line-height:1px;'
            f'mso-line-height-rule:exactly;background-color:{LINE};">&nbsp;</td></tr>')


def tag(text, tone: str = 'muted') -> Safe:
    """A small status label, as .ui-tag. A table cell, so Word keeps its padding."""
    return Safe(_tag(text, tone, rounded_in_outlook=False))


def _tag(text, tone: str, rounded_in_outlook: bool) -> str:
    """rounded_in_outlook draws a fixed-size VML shape for Outlook. Only for
    the topic tag: VML inside a table, followed by more VML, can make Word
    report the table as corrupt and show nothing."""
    color, tint = _tone(tone)
    cell = (f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="display:inline-table;vertical-align:middle;">'
            f'<tr><td class="m-{tone} m-{tone}-bg m-b" bgcolor="{tint}" style="padding:2px 8px;border-radius:6px;'
            f'background-color:{tint};color:{color};font-size:12px;font-weight:700;line-height:1.4;white-space:nowrap;">'
            f'{_e(text, "m-" + tone)}</td></tr></table>')
    if not rounded_in_outlook:
        return cell
    width = len(str(text)) * 7 + 18
    return (f'<!--[if mso]><v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" arcsize="30%" fillcolor="{tint}" stroked="f" '
            f'style="width:{width * 3 / 4:g}pt;height:15pt;v-text-anchor:middle;"><v:textbox inset="0,0,0,0">'
            f'<center style="color:{color};font-family:\'Segoe UI\',Arial,sans-serif;font-size:12px;font-weight:bold;">'
            f'{_attr(text)}</center></v:textbox></v:roundrect><![endif]-->'
            f'<!--[if !mso]><!-->{cell}<!--<![endif]-->')


def strong(text, tone: Optional[str] = None) -> Safe:
    color = _tone(tone)[0] if tone else INK
    cls = f'm-{tone}' if tone else 'm-ink'
    return Safe(f'<b class="{cls} m-b" style="color:{color};font-weight:650;">{_e(text, cls)}</b>')


def mono(text, max_length: Optional[int] = None) -> Safe:
    """Technical values (addresses, record text, keys). Long keys have no
    spaces, so they may break anywhere instead of widening the email. Word
    cannot break them at all, so max_length shortens them in the middle."""
    text = '' if text is None else str(text)
    if max_length and len(text) > max_length:
        keep = max_length - 1
        text = f'{text[:keep * 2 // 3]}…{text[-(keep - keep * 2 // 3):]}'
    return Safe(f'<span class="m-mono" style="font-family:{MONO};font-size:13px;word-break:break-all;">{_e(text)}</span>')


def link(text, url) -> Safe:
    """A link; only http(s) URLs become links, anything else stays text."""
    url = '' if url is None else str(url)
    if not url.lower().startswith(('http://', 'https://')):
        return Safe(_e(text))
    return Safe(f'<a href="{_attr(url)}" class="m-ink" style="color:{INK};text-decoration:underline !important;">{_e(text)}</a>')


def join(parts: Iterable, sep: str = ', ') -> Safe:
    return Safe(_e(sep).join(_e(p) for p in parts))


def paragraph(text, muted: bool = False) -> Safe:
    color, cls = (MUTED, 'm-muted') if muted else (INK, 'm-ink')
    return Safe(f'<p class="{cls}" style="margin:0;color:{color};font-size:15px;line-height:1.55;">{_lines(text, cls)}</p>')


def banner(tone: str, title, text=None) -> Safe:
    """A tinted message across the full width, as .ui-banner."""
    color, tint = _tone(tone)
    body = (f'<tr><td class="m-ink" style="padding:3px 16px 0;color:{INK};font-size:14px;line-height:1.5;">'
            f'{_lines(text)}</td></tr>') if text else ''
    inner = (
        f'<table {_TABLE} class="m-{tone}-bg" bgcolor="{tint}" style="background-color:{tint};border-radius:12px;">'
        f'<tr><td height="13" style="height:13px;font-size:1px;line-height:1px;">&nbsp;</td></tr>'
        f'<tr><td class="m-{tone} m-b" style="padding:0 16px;color:{color};font-size:14px;font-weight:700;line-height:1.4;">'
        f'{_lines(title, "m-" + tone)}</td></tr>{body}'
        f'<tr><td height="13" style="height:13px;font-size:1px;line-height:1px;">&nbsp;</td></tr></table>'
    )
    return Safe(inner)


Stat = Tuple  # (label, value) or (label, value, tone) or (label, value, tone, note)


def stats(items: Sequence[Stat], per_row: int = 3) -> Safe:
    """Key figures in bordered cells, as .ui-kpis. One table per row, so a
    short last row keeps the width of the others."""
    width = int(100 / per_row)
    rows = []
    for start in range(0, len(items), per_row):
        chunk = list(items[start:start + per_row])
        cells = []
        for i in range(per_row):
            if i:
                cells.append('<td width="8" style="width:8px;font-size:1px;line-height:1px;">&nbsp;</td>')
            if i >= len(chunk):
                cells.append(f'<td width="{width}%">&nbsp;</td>')
                continue
            item = chunk[i]
            label, value = item[0], item[1]
            tone = item[2] if len(item) > 2 else None
            note = item[3] if len(item) > 3 else None
            color = _tone(tone)[0] if tone else INK
            vcls = f'm-{tone}' if tone else 'm-ink'
            note_html = (f'<br><span class="m-muted" style="color:{MUTED};font-size:12px;line-height:1.4;">{_e(note, "m-muted")}</span>'
                         if note else '')
            cells.append(
                f'<td class="m-stat m-line" width="{width}%" valign="top" style="padding:11px 14px;border:1px solid {LINE};'
                f'border-radius:12px;">'
                f'<span class="m-muted" style="color:{MUTED};font-size:12.5px;line-height:1.4;">{_e(label, "m-muted")}</span><br>'
                f'<b class="{vcls} m-stat-v" style="color:{color};font-size:24px;line-height:1.3;font-weight:700;'
                f'letter-spacing:-0.02em;">{_e(value, vcls)}</b>{note_html}</td>'
            )
        rows.append(f'<table {_TABLE}><tr>{"".join(cells)}</tr></table>')
    # Outlook drops the bottom border of cards in the last row of a table, so
    # an empty 1px row closes the table
    return Safe(f'<table {_TABLE}>' + ''.join(
        f'<tr><td style="padding:{"8px" if i else "0"} 0 0;">{row}</td></tr>' for i, row in enumerate(rows))
        + '<tr><td height="1" style="height:1px;font-size:1px;line-height:1px;">&nbsp;</td></tr></table>')


def kv(rows: Sequence[Tuple]) -> Safe:
    """Label on the left, value on the right, a line between rows (.ui-kv).
    Each row is (label, value) or (label, value, tone)."""
    out = []
    for row in rows:
        label, value = row[0], row[1]
        tone = row[2] if len(row) > 2 else None
        color = _tone(tone)[0] if tone else INK
        vcls = f'm-{tone}' if tone else 'm-ink'
        # Markup such as a tag must not sit inside <b>: Word then reports the table as corrupt
        shown = value if isinstance(value, Safe) else f'<b style="font-weight:650;">{_lines(value, vcls)}</b>'
        out.append(_rule(2))
        out.append(
            f'<tr><td class="m-muted m-cell" valign="top" style="padding:9px 16px;color:{MUTED};font-size:14px;">{_e(label, "m-muted")}</td>'
            f'<td class="{vcls} m-cell" valign="top" align="right" style="padding:9px 16px;color:{color};font-size:14px;'
            f'text-align:right;overflow-wrap:break-word;">{shown}</td></tr>'
        )
    return Safe(f'<table {_TABLE}>' + ''.join(out) + '</table>')


def table(columns: Sequence[Union[str, Tuple[str, str]]], rows: Sequence[Sequence], empty: str = 'Nothing to show',
          head: bool = True) -> Safe:
    """A data table inside a panel. Columns are names or (name, 'right');
    head=False leaves out the header row."""
    cols = [(c, 'left') if isinstance(c, str) else c for c in columns]
    span = len(cols)
    out = []
    if head:
        out.append(_rule(span))
        out.append('<tr>' + ''.join(
            f'<th class="m-muted m-cell" align="{a}" style="padding:9px 16px 8px;color:{MUTED};font-size:12.5px;'
            f'font-weight:600;text-align:{a};">{_e(c, "m-muted")}</th>'
            for c, a in cols
        ) + '</tr>')
    for row in rows:
        out.append(_rule(span))
        out.append('<tr>' + ''.join(
            f'<td class="m-ink m-cell" align="{a}" valign="top" style="padding:9px 16px;'
            f'color:{INK};font-size:14px;line-height:1.45;text-align:{a};'
            f'{"white-space:nowrap;" if a == "right" else "overflow-wrap:break-word;"}">{_lines(cell)}</td>'
            for cell, (_, a) in zip(row, cols)
        ) + '</tr>')
    if not rows:
        out.append(_rule(span))
        out.append(f'<tr><td colspan="{span}" class="m-muted m-cell" style="padding:12px 16px;'
                   f'color:{MUTED};font-size:14px;">{_e(empty, "m-muted")}</td></tr>')
    return Safe(f'<table {_TABLE}>' + ''.join(out) + '</table>')


def panel(title, *blocks, count=None, note=None) -> Safe:
    """A grey panel with a heading, as .ui-panel."""
    count_html = (f' <span class="m-muted" style="color:{MUTED};font-weight:500;">{_e(count, "m-muted")}</span>'
                  if count is not None else '')
    note_html = (f'<br><span class="m-muted" style="color:{MUTED};font-size:12.5px;font-weight:400;">{_e(note, "m-muted")}</span>'
                 if note else '')
    body = ''.join(f'<tr><td>{_e(b)}</td></tr>' for b in blocks)
    inner = (
        f'<table {_TABLE} class="m-panel" bgcolor="{PANEL}" style="background-color:{PANEL};border-radius:12px;">'
        f'<tr><td class="m-ink m-cell" style="padding:13px 16px 9px;color:{INK};font-size:15px;">'
        f'<span class="m-b" style="font-weight:650;">{_e(title)}</span>{count_html}{note_html}</td></tr>'
        f'{body}<tr><td height="4" style="height:4px;font-size:1px;line-height:1px;">&nbsp;</td></tr></table>'
    )
    return Safe(inner)


def panel_text(text) -> Safe:
    """Free text inside a panel, with the panel padding."""
    return Safe(f'<table {_TABLE}>{_rule()}<tr><td class="m-ink m-cell" style="padding:10px 16px 12px;color:{INK};'
                f'font-size:14px;line-height:1.55;">{_lines(text)}</td></tr></table>')


BAR_MAX_HEIGHT = 80


def _bar_heights(counts: Sequence[int], max_height: int = BAR_MAX_HEIGHT) -> list:
    """Bar heights in px, scaled to the largest count. A count above zero
    stays visible (2px at least); zero is a 1px line, so the axis reads."""
    top = max(counts, default=0)
    return [max(2, round(c * max_height / top)) if c > 0 else 1 for c in counts]


def bar_chart(counts: Sequence[int], highlight: Iterable[int] = (), start=None, end=None, caption=None) -> Safe:
    """A row of bars inside a panel, for counts over time: the bars at the
    highlight indexes in the fail colour, the others grey (a highlighted
    count of zero stays a grey line). start and end label the two ends of
    the axis; the caption says in words what the bars show, so the email
    reads without them.

    Email clients draw no SVG or canvas, so every bar is a table cell of a
    fixed height (an attribute too, for Word) under a spacer cell. The bar
    cells are percentage widths with a 1px gap on each side, so the chart
    fits a phone and keeps a 600px email."""
    counts = [max(int(c), 0) for c in counts]
    marked = set(highlight)
    heights = _bar_heights(counts)
    share = 100 / len(counts) if counts else 100
    # Word reads whole percentages only; the style keeps the exact share
    width_attr, width = f"{int(share)}%", f"{share:.2f}%"
    cell = 'font-size:1px;line-height:1px;mso-line-height-rule:exactly;'
    columns = []
    for i, (count, height) in enumerate(zip(counts, heights)):
        hi = i in marked and count > 0
        cls, color = ('m-bar-hi', BAR_HI) if hi else ('m-bar', BAR)
        gap = BAR_MAX_HEIGHT - height
        spacer = (f'<tr><td height="{gap}" style="height:{gap}px;{cell}">&nbsp;</td></tr>' if gap else '')
        columns.append(
            f'<td width="{width_attr}" valign="bottom" style="width:{width};padding:0 1px;">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{spacer}'
            f'<tr><td class="{cls}" bgcolor="{color}" height="{height}" style="height:{height}px;'
            f'background-color:{color};{cell}">&nbsp;</td></tr></table></td>')
    bars = (f'<table role="presentation" aria-hidden="true" width="100%" cellpadding="0" cellspacing="0" border="0" '
            f'style="table-layout:fixed;"><tr>{"".join(columns)}</tr></table>')
    small = f'color:{MUTED};font-size:12px;line-height:1.4;'
    axis = (f'<table {_TABLE}><tr>'
            f'<td class="m-muted" align="left" style="{small}text-align:left;">{_e(start, "m-muted")}</td>'
            f'<td class="m-muted" align="right" style="{small}text-align:right;">{_e(end, "m-muted")}</td>'
            f'</tr></table>') if start or end else ''
    rows = [_rule(), f'<tr><td class="m-cell" style="padding:14px 16px 0;">{bars}</td></tr>']
    if axis:
        rows.append(f'<tr><td class="m-cell" style="padding:6px 16px 0;">{axis}</td></tr>')
    if caption:
        rows.append(f'<tr><td class="m-ink m-cell" style="padding:10px 16px 12px;color:{INK};font-size:14px;'
                    f'line-height:1.55;">{_lines(caption)}</td></tr>')
    else:
        rows.append('<tr><td height="12" style="height:12px;font-size:1px;line-height:1px;">&nbsp;</td></tr>')
    return Safe(f'<table {_TABLE}>' + ''.join(rows) + '</table>')


APP_ICON_CID = 'app-icon'
_APP_ICON = 'assets/icons/android-chrome-192x192.png'


@functools.lru_cache(maxsize=1)
def app_icon() -> Optional[bytes]:
    """The app icon as PNG, sent inside the email (cid:app-icon) so every
    client shows it without loading anything. None when the frontend files
    are not there (tests outside the image)."""
    here = Path(__file__).resolve()
    for root in (here.parents[2], here.parents[3]):  # /app in the image, the repository otherwise
        path = root / 'frontend' / _APP_ICON
        if path.is_file():
            return path.read_bytes()
    return None


def _mark() -> str:
    """The app icon. Without the file: the icon reduced to its log lines, a
    dark tile with three bars; Word draws neither the bars nor the rounded
    corners, so it gets a plain square instead."""
    if app_icon():
        return (f'<td width="26" height="26" valign="middle" style="width:26px;height:26px;">'
                f'<img src="cid:{APP_ICON_CID}" width="26" height="26" alt="" '
                f'style="display:block;width:26px;height:26px;border:0;"></td>')
    bar ='display:block;height:3px;border-radius:2px;background-color:#FFFFFF;margin:0 0 3px;'
    return (f'<!--[if mso]><td width="26" height="26" bgcolor="{INK}" style="width:26px;height:26px;">&nbsp;</td><![endif]-->'
            f'<!--[if !mso]><!--><td class="m-mark" width="14" height="26" valign="middle" style="width:14px;height:26px;'
            f'background-color:{INK};border-radius:7px;padding:0 6px;">'
            f'<i style="{bar}width:14px;"></i><i style="{bar}width:11px;opacity:.75;"></i>'
            f'<i style="{bar}width:8px;opacity:.5;margin:0;"></i></td><!--<![endif]-->')


def render(*, title, topic, tone: str = 'muted', intro=None, blocks: Sequence = (),
           footer=None, preheader=None, app_title: Optional[str] = None,
           when: Optional[datetime] = None) -> str:
    """
    A full email.

    title: the headline, a sentence that says what happened
    topic: what kind of email this is, shown as a tag above the title
    tone: ok / warn / fail / info / muted - the colour of the topic tag
    intro: one or two sentences under the title
    blocks: output of panel(), banner(), stats(), paragraph()
    footer: why the reader gets this email and where to change it
    """
    if app_title is None:
        try:
            from ..config import settings
            app_title = settings.app_title or 'mailcow Logs Viewer'
        except Exception:
            app_title = 'mailcow Logs Viewer'
    date = format_date(when or local_now(), time=True)
    preheader = preheader if preheader is not None else intro
    pre_html = (f'<div style="display:none;max-height:0;overflow:hidden;opacity:0;mso-hide:all;">{_attr(preheader)}'
                f'{"&nbsp;&zwnj;" * 40}</div>') if preheader else ''
    intro_html = (f'<tr><td class="m-muted" style="padding:10px 0 0;color:{MUTED};font-size:16px;line-height:1.5;">'
                  f'{_lines(intro, "m-muted")}</td></tr>' if intro else '')
    footer_text = f'Sent by {_e(app_title, "m-muted")}.' + (f' {_lines(footer, "m-muted")}' if footer else '')
    blocks_html = ''.join(f'<tr><td style="padding:0 0 14px;">{_e(b)}</td></tr>' for b in blocks)

    return f"""<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>{_attr(title)}</title>
<style>{_DARK_CSS}</style>
{_MSO_CSS}
</head>
<body class="m-bg" style="margin:0;padding:0;background-color:{BG};-webkit-text-size-adjust:100%;">
{pre_html}
<table role="presentation" class="m-bg" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:{BG};">
<tr><td align="center" class="m-wrap" style="padding:32px 24px;">
<!--[if mso]><table role="presentation" width="600" align="center" cellpadding="0" cellspacing="0" border="0"><tr><td><![endif]-->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;font-family:{FONT};">
<tr><td style="padding:0 0 28px;">
  <table {_TABLE}><tr>
    {_mark()}
    <td class="m-ink m-b" style="padding-left:10px;color:{INK};font-size:15px;font-weight:700;letter-spacing:-0.01em;">{_e(app_title)}</td>
    <td class="m-muted" align="right" style="color:{MUTED};font-size:13px;white-space:nowrap;">{_e(date, "m-muted")}</td>
  </tr></table>
</td></tr>
<tr><td style="padding:0 0 24px;">
  <table {_TABLE}>
  <tr><td>{_tag(topic, tone, rounded_in_outlook=True)}</td></tr>
  <tr><td class="m-ink m-h1 m-b" style="padding:12px 0 0;color:{INK};font-size:30px;line-height:1.15;font-weight:800;letter-spacing:-0.03em;">
    <h1 class="m-ink m-h1" style="margin:0;font-size:30px;line-height:1.15;font-weight:800;color:{INK};">{_e(title)}</h1></td></tr>
  {intro_html}
  </table>
</td></tr>
{blocks_html}
<tr><td class="m-muted m-line" style="padding:18px 0 0;border-top:1px solid {LINE};color:{MUTED};font-size:12.5px;line-height:1.5;">
  {footer_text}
</td></tr>
</table>
<!--[if mso]></td></tr></table><![endif]-->
</td></tr>
</table>
</body>
</html>"""
