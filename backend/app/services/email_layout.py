"""
HTML layout for every email the app sends, in the v3 design language.

Email clients ignore stylesheets, CSS variables and grid, so the blocks are
tables with inline styles. The colours are the light theme of
frontend/assets/css/ui.css; a <style> block switches to the dark theme in the
clients that honour prefers-color-scheme (Apple Mail, iOS, Outlook for Mac).

Every value passed to a block is escaped. Only the output of another block
(a Safe string) is inserted as markup, so callers never escape by hand:

    html = render(
        title='2 hosts are on a blacklist',
        topic='Blacklist', tone='fail',
        intro='Mail from these hosts may be rejected.',
        blocks=[panel('Hosts', table(...))],
    )
"""
import re
from datetime import datetime
from html import escape
from typing import Iterable, Optional, Sequence, Tuple, Union


class Safe(str):
    """Markup produced by this module; inserted without escaping."""


def _attr(value) -> str:
    """Escape for an attribute or a place that takes no markup."""
    if isinstance(value, Safe):
        return value
    return escape('' if value is None else str(value), quote=True)


_ADDRESS = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+')


def _e(value) -> str:
    """Escape visible text. Gmail and Outlook turn every address into a blue
    link of their own; an address that already is a link keeps the colour of
    the text around it."""
    if isinstance(value, Safe):
        return value
    return _ADDRESS.sub(
        lambda m: f'<a href="mailto:{m.group(0)}" style="color:inherit;text-decoration:none;">{m.group(0)}</a>',
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


def _lines(value) -> str:
    """Escape, then keep line breaks."""
    if isinstance(value, Safe):
        return value
    return _e(value).replace('\n', '<br>')


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

_DARK_CSS = """
:root { color-scheme: light dark; supported-color-schemes: light dark; }
@media (prefers-color-scheme: dark) {
  .m-bg { background-color: #0E1110 !important; }
  .m-panel { background-color: #171B19 !important; }
  .m-ink { color: #F2F5F3 !important; }
  .m-muted { color: #97A29C !important; }
  .m-line { border-color: #262C29 !important; }
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


def _tone(tone: Optional[str]) -> Tuple[str, str]:
    return TONES.get(tone or 'muted', TONES['muted'])


def tag(text, tone: str = 'muted') -> Safe:
    """A small status label, as .ui-tag."""
    color, tint = _tone(tone)
    return Safe(
        f'<span class="m-{tone} m-{tone}-bg" style="display:inline-block;padding:2px 8px;border-radius:6px;'
        f'background-color:{tint};color:{color};font-size:12px;font-weight:700;line-height:1.4;'
        f'white-space:nowrap;">{_e(text)}</span>'
    )


def strong(text, tone: Optional[str] = None) -> Safe:
    color = _tone(tone)[0] if tone else INK
    cls = f'm-{tone}' if tone else 'm-ink'
    return Safe(f'<b class="{cls}" style="color:{color};font-weight:650;">{_e(text)}</b>')


def mono(text) -> Safe:
    """Technical values (addresses, record text, keys). Long keys have no
    spaces, so they may break anywhere instead of widening the email."""
    return Safe(f'<span style="font-family:{MONO};font-size:13px;word-break:break-all;">{_e(text)}</span>')


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
    return Safe(f'<p class="{cls}" style="margin:0 0 14px;color:{color};font-size:15px;line-height:1.55;">{_lines(text)}</p>')


def banner(tone: str, title, text=None) -> Safe:
    """A tinted message across the full width, as .ui-banner."""
    color, tint = _tone(tone)
    body = (f'<div class="m-ink" style="margin-top:3px;color:{INK};font-size:14px;font-weight:400;line-height:1.5;">'
            f'{_lines(text)}</div>') if text else ''
    return Safe(
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 14px;">'
        f'<tr><td class="m-{tone}-bg" style="padding:13px 16px;border-radius:12px;background-color:{tint};">'
        f'<div class="m-{tone}" style="color:{color};font-size:14px;font-weight:700;line-height:1.4;">{_lines(title)}</div>'
        f'{body}</td></tr></table>'
    )


Stat = Tuple  # (label, value) or (label, value, tone) or (label, value, tone, note)


def stats(items: Sequence[Stat], per_row: int = 3) -> Safe:
    """Key figures in bordered cells, as .ui-kpis. Stacks on phones."""
    rows = []
    for start in range(0, len(items), per_row):
        cells = []
        chunk = list(items[start:start + per_row])
        width = int(100 / per_row)
        for i, item in enumerate(chunk):
            label, value = item[0], item[1]
            tone = item[2] if len(item) > 2 else None
            note = item[3] if len(item) > 3 else None
            color = _tone(tone)[0] if tone else INK
            vcls = f'm-{tone}' if tone else 'm-ink'
            note_html = (f'<div class="m-muted" style="margin-top:2px;color:{MUTED};font-size:12px;">{_e(note)}</div>'
                         if note else '')
            if i:
                cells.append('<td class="m-stat-gap" width="8" style="width:8px;font-size:0;">&nbsp;</td>')
            cells.append(
                f'<td class="m-stat m-line" width="{width}%" valign="top" style="padding:11px 14px;border:1px solid {LINE};'
                f'border-radius:12px;">'
                f'<div class="m-muted" style="color:{MUTED};font-size:12.5px;line-height:1.4;">{_e(label)}</div>'
                f'<div class="{vcls} m-stat-v" style="color:{color};font-size:24px;line-height:1.2;font-weight:750;'
                f'letter-spacing:-0.02em;">{_e(value)}</div>{note_html}</td>'
            )
        for _ in range(per_row - len(chunk)):
            cells.append('<td class="m-stat-gap" width="8" style="width:8px;font-size:0;">&nbsp;</td>'
                         f'<td class="m-stat-gap" width="{width}%">&nbsp;</td>')
        rows.append(f'<tr>{"".join(cells)}</tr>')
    gap = '<tr><td style="height:8px;font-size:0;line-height:0;">&nbsp;</td></tr>'
    return Safe(
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        'style="margin:0 0 14px;border-collapse:separate;">' + gap.join(rows) + '</table>'
    )


def kv(rows: Sequence[Tuple]) -> Safe:
    """Label on the left, value on the right, a line between rows (.ui-kv).
    Each row is (label, value) or (label, value, tone)."""
    out = []
    for i, row in enumerate(rows):
        label, value = row[0], row[1]
        tone = row[2] if len(row) > 2 else None
        color = _tone(tone)[0] if tone else INK
        vcls = f'm-{tone}' if tone else 'm-ink'
        border = f'border-top:1px solid {LINE};' if i else ''
        out.append(
            f'<tr><td class="m-muted m-line" valign="top" style="padding:9px 16px;{border}color:{MUTED};font-size:14px;">{_e(label)}</td>'
            f'<td class="{vcls} m-line" valign="top" align="right" style="padding:9px 16px;{border}color:{color};font-size:14px;'
            f'font-weight:650;text-align:right;overflow-wrap:break-word;">{_lines(value)}</td></tr>'
        )
    return Safe('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">' + ''.join(out) + '</table>')


def table(columns: Sequence[Union[str, Tuple[str, str]]], rows: Sequence[Sequence], empty: str = 'Nothing to show',
          head: bool = True) -> Safe:
    """A data table inside a panel. Columns are names or (name, 'right');
    head=False leaves out the header row."""
    cols = [(c, 'left') if isinstance(c, str) else c for c in columns]
    head_html = ''.join(
        f'<th class="m-muted m-line m-cell" align="{a}" style="padding:9px 16px 8px;border-top:1px solid {LINE};color:{MUTED};font-size:12.5px;font-weight:600;'
        f'text-align:{a};">{_e(c)}</th>'
        for c, a in cols
    )
    body = []
    for row in rows:
        body.append('<tr>' + ''.join(
            f'<td class="m-ink m-line m-cell" align="{a}" valign="top" style="padding:9px 16px;border-top:1px solid {LINE};'
            f'color:{INK};font-size:14px;line-height:1.45;text-align:{a};'
            f'{"white-space:nowrap;" if a == "right" else "overflow-wrap:break-word;"}">{_lines(cell)}</td>'
            for cell, (_, a) in zip(row, cols)
        ) + '</tr>')
    if not body:
        body.append(f'<tr><td colspan="{len(cols)}" class="m-muted m-line" style="padding:12px 16px;border-top:1px solid {LINE};'
                    f'color:{MUTED};font-size:14px;">{_e(empty)}</td></tr>')
    return Safe('<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
                f'{f"<tr>{head_html}</tr>" if head else ""}{"".join(body)}</table>')


def panel(title, *blocks, count=None, note=None) -> Safe:
    """A grey panel with a heading, as .ui-panel."""
    count_html = (f' <span class="m-muted" style="color:{MUTED};font-weight:500;">{_e(count)}</span>'
                  if count is not None else '')
    note_html = (f'<div class="m-muted" style="margin-top:2px;color:{MUTED};font-size:12.5px;font-weight:400;">{_e(note)}</div>'
                 if note else '')
    return Safe(
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 14px;">'
        f'<tr><td class="m-panel" style="background-color:{PANEL};border-radius:12px;padding:0 0 4px;">'
        f'<div class="m-ink" style="padding:13px 16px 9px;color:{INK};font-size:15px;font-weight:650;">{_e(title)}{count_html}{note_html}</div>'
        f'{"".join(_e(b) for b in blocks)}</td></tr></table>'
    )


def panel_text(text) -> Safe:
    """Free text inside a panel, with the panel padding."""
    return Safe(f'<div class="m-ink m-line" style="padding:10px 16px 12px;border-top:1px solid {LINE};color:{INK};'
                f'font-size:14px;line-height:1.55;">{_lines(text)}</div>')


def _mark() -> str:
    """The app icon reduced to its log lines: a dark tile with three bars."""
    bar = 'display:block;height:3px;border-radius:2px;background-color:#FFFFFF;margin:0 0 3px;'
    return (f'<td class="m-mark" width="14" height="26" valign="middle" style="width:14px;height:26px;background-color:{INK};'
            f'border-radius:7px;padding:0 6px;">'
            f'<i style="{bar}width:14px;"></i><i style="{bar}width:11px;opacity:.75;"></i><i style="{bar}width:8px;opacity:.5;margin:0;"></i></td>')


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
    intro_html = (f'<p class="m-muted" style="margin:10px 0 0;color:{MUTED};font-size:16px;line-height:1.5;">{_lines(intro)}</p>'
                  if intro else '')
    footer_text = f'Sent by {_e(app_title)}.' + (f' {_lines(footer)}' if footer else '')

    return f"""<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>{_attr(title)}</title>
<style>{_DARK_CSS}</style>
</head>
<body class="m-bg" style="margin:0;padding:0;background-color:{BG};-webkit-text-size-adjust:100%;">
{pre_html}
<table role="presentation" class="m-bg" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:{BG};">
<tr><td align="center" class="m-wrap" style="padding:32px 24px;">
<!--[if mso]><table role="presentation" width="600" align="center" cellpadding="0" cellspacing="0" border="0"><tr><td><![endif]-->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;font-family:{FONT};">
<tr><td style="padding:0 0 28px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
    {_mark()}
    <td class="m-ink" style="padding-left:10px;color:{INK};font-size:15px;font-weight:700;letter-spacing:-0.01em;">{_e(app_title)}</td>
    <td class="m-muted" align="right" style="color:{MUTED};font-size:13px;white-space:nowrap;">{_e(date)}</td>
  </tr></table>
</td></tr>
<tr><td style="padding:0 0 24px;">
  {tag(topic, tone)}
  <h1 class="m-ink m-h1" style="margin:12px 0 0;color:{INK};font-size:30px;line-height:1.15;font-weight:800;letter-spacing:-0.03em;">{_e(title)}</h1>
  {intro_html}
</td></tr>
<tr><td>{"".join(_e(b) for b in blocks)}</td></tr>
<tr><td class="m-muted m-line" style="padding:18px 0 0;margin-top:10px;border-top:1px solid {LINE};color:{MUTED};font-size:12.5px;line-height:1.5;">
  {footer_text}
</td></tr>
</table>
<!--[if mso]></td></tr></table><![endif]-->
</td></tr>
</table>
</body>
</html>"""
