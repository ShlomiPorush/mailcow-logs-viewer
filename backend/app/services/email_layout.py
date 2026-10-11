"""
HTML layout for every email the app sends, in the v3 design language.

Email clients ignore stylesheets, CSS variables and grid, so the blocks are
tables with inline styles. The colours are the light theme of
frontend/assets/css/ui.css; a <style> block switches to the dark theme in the
clients that honour prefers-color-scheme (Apple Mail, iOS, Outlook for Mac).

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


class Safe(str):
    """Markup produced by this module; inserted without escaping."""


def _attr(value) -> str:
    """Escape for an attribute or a place that takes no markup."""
    if isinstance(value, Safe):
        return value
    return escape('' if value is None else str(value), quote=True)


_ADDRESS = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+')


def _e(value, cls: str = 'm-ink') -> str:
    """Escape visible text whose colour class is cls. Gmail and Outlook turn
    every address into a blue link of their own, and Outlook ignores
    color:inherit, so an address becomes a link of ours in the text colour."""
    if isinstance(value, Safe):
        return value
    color = _CLASS_COLORS.get(cls, INK)
    return _ADDRESS.sub(
        lambda m: f'<a href="mailto:{m.group(0)}" class="{cls}" style="color:{color};text-decoration:none;">{m.group(0)}</a>',
        _attr(value))


def local_now() -> datetime:
    """Now, in the timezone set in TZ, like the dates in the app."""
    from zoneinfo import ZoneInfo
    try:
        from ..config import settings
        return datetime.now(ZoneInfo(settings.tz or 'UTC'))
    except Exception:
        return datetime.now(ZoneInfo('UTC'))


def format_date(when: datetime, time: bool = False) -> str:
    """Day/month/year, as the old emails and the numeric dates in the app."""
    return when.strftime('%d/%m/%Y %H:%M' if time else '%d/%m/%Y')


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
}
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
.m-vml { background-color: transparent !important; border: none !important; padding: 0 !important; }
</style><![endif]-->"""

# Word draws no rounded corners, so Outlook for Windows gets a VML rounded
# rectangle behind each panel, banner, card and tag. Its corner is a share
# of the shorter side, so the height is estimated to keep about 12px.
_ROW_HEIGHT = 37


def _rounded(inner: str, width: int, height: int, fill: str, stroke: Optional[str] = None,
             radius: int = 12, padding: Optional[str] = None, only_mso: bool = False) -> str:
    """inner in a VML rounded rectangle for Outlook; other clients get inner
    as it is (the block's own background has class m-vml, so Outlook leaves
    it transparent). padding is the inner padding Outlook takes from the
    shape. only_mso: the caller already sits in an mso-only comment."""
    # arcsize is the corner radius as a share of the shorter side
    arc = max(1, min(50, round(radius * 100 / min(width, height))))
    edge = f'strokecolor="{stroke}" strokeweight="0.75pt"' if stroke else 'stroked="f"'
    pad_open = f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding:{padding};">' if padding else ''
    pad_close = '</td></tr></table>' if padding else ''
    shape_open = (f'<v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" arcsize="{arc}%" fillcolor="{fill}" {edge} '
                  f'style="width:{width * 3 / 4:g}pt;mso-fit-shape-to-text:true;"><v:textbox inset="0,0,0,0" '
                  f'style="mso-fit-shape-to-text:true;">{pad_open}')
    shape_close = f'{pad_close}</v:textbox></v:roundrect>'
    if only_mso:
        return f'{shape_open}{inner}{shape_close}'
    return f'<!--[if mso]>{shape_open}<![endif]-->{inner}<!--[if mso]>{shape_close}<![endif]-->'


def _estimate_height(html: str) -> int:
    rows = html.count('<tr') - html.count('class="m-rule"')
    return max(40, rows * _ROW_HEIGHT + html.count('<br>') * 20)

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
    """rounded_in_outlook draws a VML shape for Outlook. Only for a tag that
    is not inside another rounded block: VML inside VML, followed by more
    VML, makes Word report the table as corrupt and show nothing."""
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
    return Safe(f'<a href="{_attr(url)}" class="m-ink" style="color:{INK};text-decoration:underline;">{_e(text)}</a>')


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
        f'<table {_TABLE} class="m-{tone}-bg m-vml" style="background-color:{tint};border-radius:12px;">'
        f'<tr><td height="13" style="height:13px;font-size:1px;line-height:1px;">&nbsp;</td></tr>'
        f'<tr><td class="m-{tone} m-b" style="padding:0 16px;color:{color};font-size:14px;font-weight:700;line-height:1.4;">'
        f'{_lines(title, "m-" + tone)}</td></tr>{body}'
        f'<tr><td height="13" style="height:13px;font-size:1px;line-height:1px;">&nbsp;</td></tr></table>'
    )
    lines = 1 + (len(str(text or '')) // 80 + 1 + str(text or '').count('\n') if text else 0)
    return Safe(_rounded(inner, 600, 26 + lines * 21, tint))


Stat = Tuple  # (label, value) or (label, value, tone) or (label, value, tone, note)


def stats(items: Sequence[Stat], per_row: int = 3) -> Safe:
    """Key figures in bordered cells, as .ui-kpis. One table per row, so a
    short last row keeps the width of the others."""
    width = int(100 / per_row)
    card = (600 - 8 * (per_row - 1)) // per_row
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
            content = (
                f'<span class="m-muted" style="color:{MUTED};font-size:12.5px;line-height:1.4;">{_e(label, "m-muted")}</span><br>'
                f'<b class="{vcls} m-stat-v" style="color:{color};font-size:24px;line-height:1.3;font-weight:700;'
                f'letter-spacing:-0.02em;">{_e(value, vcls)}</b>{note_html}'
            )
            # Outlook gets only the VML card, the others only the bordered cell
            cells.append(
                f'<td width="{width}%" valign="top">'
                f'<!--[if mso]>{_rounded(content, card, 100, BG, stroke=LINE, padding="11px 14px", only_mso=True)}<![endif]-->'
                f'<!--[if !mso]><!--><table {_TABLE}><tr><td class="m-stat m-line" valign="top" '
                f'style="padding:11px 14px;border:1px solid {LINE};border-radius:12px;">{content}</td></tr></table><!--<![endif]-->'
                f'</td>'
            )
        rows.append(f'<table {_TABLE}><tr>{"".join(cells)}</tr></table>')
    return Safe(f'<table {_TABLE}>' + ''.join(
        f'<tr><td style="padding:{"8px" if i else "0"} 0 0;">{row}</td></tr>' for i, row in enumerate(rows)) + '</table>')


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
        f'<table {_TABLE} class="m-panel m-vml" style="background-color:{PANEL};border-radius:12px;">'
        f'<tr><td class="m-ink m-cell" style="padding:13px 16px 9px;color:{INK};font-size:15px;">'
        f'<span class="m-b" style="font-weight:650;">{_e(title)}</span>{count_html}{note_html}</td></tr>'
        f'{body}<tr><td height="4" style="height:4px;font-size:1px;line-height:1px;">&nbsp;</td></tr></table>'
    )
    return Safe(_rounded(inner, 600, _estimate_height(inner), PANEL))


def panel_text(text) -> Safe:
    """Free text inside a panel, with the panel padding."""
    return Safe(f'<table {_TABLE}>{_rule()}<tr><td class="m-ink m-cell" style="padding:10px 16px 12px;color:{INK};'
                f'font-size:14px;line-height:1.55;">{_lines(text)}</td></tr></table>')


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
