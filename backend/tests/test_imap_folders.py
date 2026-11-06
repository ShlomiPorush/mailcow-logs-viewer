"""Several IMAP folders for the DMARC & TLS report import (issue #564): the
stored setting, the folder list, which folders a run reads, and a run across
folders against a fake IMAP server. Nothing leaves the test."""
import imaplib
import secrets
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import app.services.dmarc_imap_service as imap_module
from app.services import connection_test
from app.services.dmarc_imap_service import DMARCImapService
from app.services.imap_folders import (Entry, Folder, decode_mutf7, describe_setting, folder_targets,
                                       legacy_match, parse_list, parse_setting, resolve)


# ---------------------------------------------------------------- the setting

@pytest.mark.parametrize('value', ['INBOX', 'inbox', 'Reports', '[Gmail]/Spam', 'Reports,Archive', '[]',
                                   'Reports/&ZeVnLIqe-', 'x/*', '{"name": "a"}', '[1]', '[""]',
                                   '[{"name": "a", "other": 1}]', '["a", {"name": "b", "subfolders": "yes"}]'])
def test_anything_but_a_folder_list_is_one_folder_as_stored(value):
    assert parse_setting(value) == (None, value)


@pytest.mark.parametrize('value', [None, '', '   '])
def test_no_value_is_the_inbox(value):
    assert parse_setting(value) == (None, 'INBOX')


def test_folder_list():
    entries, legacy = parse_setting('[{"name":"INBOX/dmarc","subfolders":true},"INBOX/tls-rpt",{"name":"x"}]')
    assert legacy is None
    assert entries == [Entry('INBOX/dmarc', True), Entry('INBOX/tls-rpt'), Entry('x')]
    assert describe_setting('[{"name":"INBOX/dmarc","subfolders":true},"INBOX/tls-rpt"]') == \
        'INBOX/dmarc (with subfolders), INBOX/tls-rpt'
    assert describe_setting('Reports') == 'Reports'


# ---------------------------------------------------------------- the folder list

def test_modified_utf7():
    # RFC 3501, 5.1.3
    assert decode_mutf7('~peter/mail/&U,BTFw-/&ZeVnLIqe-') == '~peter/mail/\u53f0\u5317/\u65e5\u672c\u8a9e'
    assert decode_mutf7('Tom &- Jerry') == 'Tom & Jerry'
    assert decode_mutf7('&BdMF1QXXBdUF6g-') == '\u05d3\u05d5\u05d7\u05d5\u05ea'
    for bad in ('&ZeVn', '&!!!-', '&AA-'):
        with pytest.raises(ValueError):
            decode_mutf7(bad)


def test_list_answer_as_imaplib_returns_it():
    data = [
        b'(\\HasChildren) "/" INBOX',
        b'(\\HasNoChildren) "/" "INBOX/with \\"quotes\\" and \\\\ back"',
        b'(\\Noselect \\HasChildren) "/" "Archive"',
        b'(\\HasNoChildren) "/" "Reports/&BdMF1QXXBdUF6g-"',
        (b'(\\HasNoChildren) "/" {11}', b'INBOX/{lit}'), b'',
        b'(\\Noinferiors) NIL "Flat"',
        b'(\\HasNoChildren) "." "dotted.name"',
        b'garbage',
        b'(\\HasNoChildren) "/" "unterminated',
    ]
    folders, unreadable = parse_list(data)
    assert unreadable == 2
    assert [(f.raw, f.name, f.delimiter, f.selectable, f.can_have_children) for f in folders] == [
        ('INBOX', 'INBOX', '/', True, True),
        ('INBOX/with "quotes" and \\ back', 'INBOX/with "quotes" and \\ back', '/', True, True),
        ('Archive', 'Archive', '/', False, True),
        ('Reports/&BdMF1QXXBdUF6g-', 'Reports/\u05d3\u05d5\u05d7\u05d5\u05ea', '/', True, True),
        ('INBOX/{lit}', 'INBOX/{lit}', '/', True, True),
        ('Flat', 'Flat', None, True, False),
        ('dotted.name', 'dotted.name', '.', True, True),
    ]


def _folders(*names, noselect=(), delimiter='/'):
    return [Folder(raw=n, name=decode_mutf7(n), delimiter=delimiter,
                   flags=frozenset({'\\noselect'} if n in noselect else set())) for n in names]


def test_subfolders_are_matched_by_exact_name_never_as_a_pattern():
    folders = _folders('INBOX', 'Reports%', 'Reports%/a', 'ReportsX', 'ReportsX/b', 'Reports*', 'Reports*/c')
    targets, missing, empty = resolve(folders, [Entry('Reports%', True), Entry('Reports*', True)])
    assert [t.label for t in targets] == ['Reports%', 'Reports%/a', 'Reports*', 'Reports*/c']
    assert missing == [] and empty == []


def test_folders_added_later_are_read_and_direct_choice_wins():
    folders = _folders('INBOX', 'INBOX/dmarc', 'INBOX/dmarc/google.com', 'INBOX/dmarc/new-tag', 'INBOX/tls-rpt')
    targets, missing, empty = resolve(folders, [Entry('inbox/dmarc', True), Entry('INBOX/dmarc', True),
                                                Entry('INBOX/dmarc/new-tag'), Entry('gone')])
    # Names other than INBOX itself are exact: inbox/dmarc is not INBOX/dmarc
    assert missing == ['inbox/dmarc', 'gone']
    assert [(t.label, t.direct) for t in targets] == [
        ('INBOX/dmarc', True), ('INBOX/dmarc/google.com', False), ('INBOX/dmarc/new-tag', True)]
    assert targets[0].select == '"INBOX/dmarc"'


def test_inbox_is_case_insensitive_and_noselect_parents():
    folders = _folders('INBOX', 'Archive', 'Archive/2026', 'Empty', noselect=('Archive', 'Empty'))
    targets, missing, empty = resolve(folders, [Entry('inbox'), Entry('Archive', True), Entry('Empty', True),
                                                Entry('Empty')])
    assert [(t.label, t.direct) for t in targets] == [('INBOX', True), ('Archive/2026', False)]
    # A parent with subfolders and nothing to read yet is not missing; a \Noselect folder named itself is
    assert empty == ['Empty'] and missing == ['Empty']


def test_a_stored_single_name_matches_the_raw_listed_name():
    folders = _folders('INBOX', 'Reports/&ZeVnLIqe-')
    assert legacy_match(folders, 'Reports/&ZeVnLIqe-') == 'Reports/\u65e5\u672c\u8a9e'
    assert legacy_match(folders, 'inbox') == 'INBOX'
    assert legacy_match(folders, 'Reports/\u65e5\u672c\u8a9e') is None


# ---------------------------------------------------------------- a fake server

class Server:
    """An IMAP server with folders of mails, answering as imaplib returns it.
    keep_seen=False: STORE answers OK but the flag does not stay."""

    def __init__(self, folders, uidplus=True, keep_seen=True, list_extra=(), noselect=()):
        self.folders = {name: {str(uid): dict(mail) for uid, mail in mails.items()} for name, mails in folders.items()}
        self.uidplus, self.keep_seen = uidplus, keep_seen
        self.list_extra, self.noselect = list(list_extra), set(noselect)
        self.selected = None
        self.calls = []

    def capability(self):
        return 'OK', [b'IMAP4rev1 IDLE' + (b' UIDPLUS' if self.uidplus else b'')]

    def list(self, directory='""', pattern='*'):
        self.calls.append(('LIST', directory, pattern))
        lines = []
        for name in self.folders:
            flags = '\\Noselect' if name in self.noselect else '\\HasNoChildren'
            lines.append(f'({flags}) "/" "{name}"'.encode())
        return 'OK', lines + self.list_extra

    def select(self, mailbox, readonly=False):
        self.calls.append(('SELECT', mailbox))
        name = mailbox[1:-1] if mailbox.startswith('"') else mailbox
        if name not in self.folders or name in self.noselect:
            return 'NO', [b'Mailbox does not exist']
        self.selected = name
        return 'OK', [str(len(self.folders[name])).encode()]

    def uid(self, command, *args):
        mails = self.folders[self.selected]
        self.calls.append((command, self.selected) + args)
        if command == 'SEARCH':
            unseen = [uid for uid, mail in mails.items() if 'seen' not in mail.get('flags', set())]
            if 'SUBJECT' in args[1]:
                unseen = [uid for uid in unseen if mails[uid].get('report')]
            return 'OK', [' '.join(unseen).encode()]
        if command == 'STORE':
            uid, _, flag = args
            if flag == '\\Seen' and not self.keep_seen:
                return 'OK', [b'']
            mails[uid].setdefault('flags', set()).add('seen' if flag == '\\Seen' else 'deleted')
            return 'OK', [b'']
        if command == 'EXPUNGE':
            for uid in args[0].split(','):
                if 'deleted' in mails[uid].get('flags', set()):
                    del mails[uid]
            return 'OK', [b'']
        raise AssertionError(command)

    def expunge(self):
        raise AssertionError('a plain EXPUNGE removes every deleted email of the folder')

    def logout(self):
        return 'BYE', [b'']


class _SyncRecord(SimpleNamespace):
    def __init__(self, **kwargs):
        super().__init__(id=1, emails_found=0, emails_processed=0, reports_created=0,
                         reports_duplicate=0, reports_failed=0, error_message=None,
                         failed_emails=None, completed_at=None, **kwargs)


def _run(monkeypatch, server, setting, delete_after=False, scan_all_unseen=False):
    """One import run against the server; process_email answers from each mail's
    'result' (default: a stored report), so no database is involved."""
    service = DMARCImapService()
    service.folder = setting
    service.delete_after = delete_after
    service.scan_all_unseen = scan_all_unseen
    service.batch_size = 2
    service.connection = server

    def connect():
        status, data = server.capability()
        service.uidplus = b'UIDPLUS' in data[0].split()
        return True
    processed = []

    def process_email(email_id, db):
        mail = server.folders[server.selected][email_id]
        processed.append((server.selected, email_id))
        result = {'success': True, 'reports_created': 1, 'reports_duplicate': 0, 'error': None,
                  'message_id': f'<{email_id}@x>', 'subject': 'Report Domain: x', 'skipped': None, 'keep': False}
        result.update(mail.get('result', {}))
        return result
    monkeypatch.setattr(service, 'connect', connect)
    monkeypatch.setattr(service, 'disconnect', lambda: None)
    monkeypatch.setattr(service, 'process_email', process_email)
    monkeypatch.setattr(imap_module, 'SessionLocal', Mock)
    monkeypatch.setattr(imap_module, 'DMARCSync', _SyncRecord)
    cleared = []
    monkeypatch.setattr(imap_module, 'clear_dmarc_cache', lambda db: cleared.append(1))
    notified = []
    monkeypatch.setattr(imap_module, 'send_dmarc_error_notification',
                        lambda failed, sync_id: notified.append(failed) or True)
    result = service.sync_reports()
    return result, processed, cleared, notified


REPORT = {'report': True}


def test_a_run_reads_every_chosen_folder_and_subfolders_added_later(monkeypatch):
    server = Server({'INBOX': {1: REPORT}, 'INBOX/dmarc': {1: REPORT},
                     'INBOX/dmarc/google.com': {1: REPORT, 2: {'report': True, 'result': {
                         'success': False, 'reports_created': 0, 'error': 'broken'}}},
                     'INBOX/dmarc/added-later': {7: REPORT}, 'Other': {1: REPORT}})
    result, processed, cleared, notified = _run(monkeypatch, server, '[{"name":"INBOX/dmarc","subfolders":true}]')
    assert result['status'] == 'success'
    # The same UID in different folders is a different email
    assert processed == [('INBOX/dmarc', '1'), ('INBOX/dmarc/google.com', '1'), ('INBOX/dmarc/google.com', '2'),
                         ('INBOX/dmarc/added-later', '7')]
    assert result['emails_found'] == 4 and result['reports_created'] == 3
    assert result['failed_emails'] == [{'email_id': '2', 'folder': 'INBOX/dmarc/google.com',
                                        'message_id': '<2@x>', 'subject': 'Report Domain: x', 'error': 'broken'}]
    assert notified and cleared
    # One LIST of every folder; no stored name is sent as a pattern
    assert [c for c in server.calls if c[0] == 'LIST'] == [('LIST', '""', '*')]


def test_delete_removes_only_the_imported_email(monkeypatch):
    foreign = {'flags': {'seen', 'deleted'}}
    server = Server({'INBOX/dmarc': {1: REPORT, 2: foreign, 3: {'report': True, 'result': {'keep': True}}}})
    result, *_ = _run(monkeypatch, server, '["INBOX/dmarc"]', delete_after=True)
    assert result['status'] == 'success'
    # The report is gone; a mail client's deleted email and a kept report stay
    assert sorted(server.folders['INBOX/dmarc']) == ['2', '3']
    assert ('EXPUNGE', 'INBOX/dmarc', '1') in server.calls


def test_without_uidplus_imported_emails_are_only_marked(monkeypatch):
    server = Server({'INBOX': {1: REPORT}}, uidplus=False)
    result, *_ = _run(monkeypatch, server, 'INBOX', delete_after=True)
    assert result['status'] == 'success'
    assert server.folders['INBOX']['1']['flags'] == {'deleted', 'seen'}
    assert not [c for c in server.calls if c[0] == 'EXPUNGE']


def test_scan_all_unseen_only_in_folders_chosen_themselves(monkeypatch):
    personal = {'result': {'skipped': 'no report attached', 'reports_created': 0}}
    server = Server({'INBOX': {1: personal}, 'INBOX/sub': {1: personal, 2: REPORT}})
    result, processed, *_ = _run(monkeypatch, server, '[{"name":"INBOX","subfolders":true}]', scan_all_unseen=True)
    assert result['status'] == 'success'
    assert processed == [('INBOX', '1'), ('INBOX/sub', '2')]
    # The personal email under the parent is not marked as read
    assert 'flags' not in server.folders['INBOX/sub']['1']


def test_a_missing_folder_does_not_stop_the_others(monkeypatch):
    server = Server({'INBOX/tls-rpt': {1: REPORT}, 'Shared': {}}, noselect=('Shared',))
    result, processed, *_ = _run(monkeypatch, server, '["INBOX/dmarc","INBOX/tls-rpt","Shared"]')
    assert processed == [('INBOX/tls-rpt', '1')]
    assert result['status'] == 'error'
    assert result['error_message'] == 'Folder not found or not readable: INBOX/dmarc, Shared'


def test_a_stored_single_name_is_selected_as_stored_without_listing(monkeypatch):
    server = Server({'inbox': {1: REPORT}, 'Reports/&ZeVnLIqe-': {}})
    result, processed, *_ = _run(monkeypatch, server, 'inbox')
    assert result['status'] == 'success' and processed == [('inbox', '1')]
    assert ('SELECT', 'inbox') in server.calls
    assert not [c for c in server.calls if c[0] == 'LIST']
    _run(monkeypatch, server, 'Reports/&ZeVnLIqe-')
    assert ('SELECT', 'Reports/&ZeVnLIqe-') in server.calls
    result, *_ = _run(monkeypatch, server, 'Gone')
    assert result['status'] == 'error' and result['error_message'] == 'Failed to select folder Gone'


def test_flags_the_server_does_not_keep_stop_the_folder(monkeypatch):
    server = Server({'INBOX': {1: REPORT, 2: REPORT, 3: REPORT}}, keep_seen=False)
    result, processed, *_ = _run(monkeypatch, server, 'INBOX')
    assert result['status'] == 'error'
    assert 'already handled as unread' in result['error_message']
    # Each email once, no endless loop
    assert processed == [('INBOX', '1'), ('INBOX', '2'), ('INBOX', '3')]
    assert result['emails_processed'] == 3


def test_a_refused_search_or_store_is_an_error_not_an_empty_folder(monkeypatch):
    server = Server({'INBOX': {1: REPORT}})
    real_uid = server.uid
    monkeypatch.setattr(server, 'uid', lambda command, *args: ('NO', [b'busy']) if command == 'SEARCH'
                        else real_uid(command, *args))
    result, *_ = _run(monkeypatch, server, 'INBOX')
    assert result['status'] == 'error' and 'refused the search' in result['error_message']

    server = Server({'INBOX': {1: REPORT}})
    real_uid = server.uid
    monkeypatch.setattr(server, 'uid', lambda command, *args: ('NO', [b'read-only']) if command == 'STORE'
                        else real_uid(command, *args))
    result, processed, cleared, _ = _run(monkeypatch, server, 'INBOX')
    assert result['status'] == 'error' and 'refused to set' in result['error_message']
    assert processed == [('INBOX', '1')]
    # The report was stored before the error: the DMARC pages must show it
    assert cleared


def test_unreadable_list_lines_end_the_run_with_an_error_after_the_readable_folders(monkeypatch):
    server = Server({'INBOX/dmarc': {1: REPORT}}, list_extra=[b'(\\HasNoChildren) "/" "broken'])
    result, processed, *_ = _run(monkeypatch, server, '[{"name":"INBOX/dmarc","subfolders":true}]')
    assert processed == [('INBOX/dmarc', '1')]
    assert result['status'] == 'error'
    assert result['error_message'] == "1 folders could not be read from the server's folder list"


def test_capabilities_are_read_again_after_login(monkeypatch):
    class Imap:
        capabilities = ('IMAP4REV1',)

        def __init__(self, host, port, timeout=None):
            pass

        def login(self, user, password):
            return 'OK', [b'']

        def capability(self):
            return 'OK', [b'IMAP4rev1 UIDPLUS MOVE']
    monkeypatch.setattr(imap_module.imaplib, 'IMAP4', Imap)
    service = DMARCImapService()
    service.host, service.port, service.use_ssl = 'imap.example', 143, False
    service.connect()
    assert service.uidplus is True


def test_folder_targets_for_the_test_and_the_picker():
    server = Server({'INBOX': {}, 'INBOX/dmarc': {}})
    targets, missing, empty, unreadable = folder_targets(server, '["INBOX/dmarc"]')
    assert [t.select for t in targets] == ['"INBOX/dmarc"'] and not (missing or empty or unreadable)


def test_folder_list_answer(monkeypatch):
    from app.config import settings
    password = secrets.token_urlsafe(24)
    for key, value in (('dmarc_imap_host', 'imap.example'), ('dmarc_imap_user', 'reports'),
                       ('dmarc_imap_password', password),
                       ('dmarc_imap_folder', 'Reports/&ZeVnLIqe-')):
        monkeypatch.setattr(settings._inner, key, value)
    server = Server({'INBOX': {}, 'Reports/&ZeVnLIqe-': {}})
    monkeypatch.setattr(connection_test, '_open_imap', lambda current: server)
    answer = connection_test.list_imap_folders()
    assert answer['ok'] is True and answer['user'] == 'reports'
    assert [f['name'] for f in answer['folders']] == ['INBOX', 'Reports/\u65e5\u672c\u8a9e']
    assert answer['legacy'] == {'value': 'Reports/&ZeVnLIqe-', 'name': 'Reports/\u65e5\u672c\u8a9e'}
    assert password not in repr(answer)

    monkeypatch.setattr(settings._inner, 'dmarc_imap_password', None)
    answer = connection_test.list_imap_folders()
    assert answer['ok'] is False and answer['error'] == 'not_configured'


def test_history_hides_the_folder_from_callers_without_settings(monkeypatch):
    from app.routers import dmarc
    monkeypatch.setattr(dmarc, 'job_error', lambda request, error: 'hidden' if request == 'viewer' else error)
    item = {'email_id': '2', 'folder': 'INBOX/private', 'message_id': None, 'subject': None, 'error': 'x'}
    assert dmarc._failure_for('viewer', item, False) == {
        'email_id': '2', 'message_id': None, 'subject': None, 'error': 'hidden'}
    assert dmarc._failure_for('admin', item, True) == item
    # Entries from runs before folder lists have no folder
    assert dmarc._failure_for('admin', {'email_id': '1', 'error': 'x'}, True) == {'email_id': '1', 'error': 'x'}


def test_hostile_list_answers_are_not_offered_or_read():
    data = [
        b'(\HasNoChildren) "/" "Reports"',
        # A line break in a name would start another command when the name is sent back
        (b'(\HasNoChildren) "/" {27}', b'Reports/x\r\na LOGOUT\r\nb NOOP'), b'',
        # An empty separator would make "Reports" cover "ReportsPrivate"
        b'(\HasNoChildren) "" "ReportsPrivate"',
        # NUL through modified UTF-7
        b'(\HasNoChildren) "/" "Reports/&AAA-"',
        # A second spelling of a listed name: neither can be told apart
        b'(\HasNoChildren) "/" "Dup"', b'(\HasNoChildren) "/" "&AEQAdQBw-"',
    ]
    folders, unreadable = parse_list(data)
    assert [f.raw for f in folders] == ['Reports']
    assert unreadable == 5
    targets, missing, empty = resolve(folders, [Entry('Reports', True)])
    assert [t.label for t in targets] == ['Reports']


def test_a_read_only_folder_does_not_stop_the_others(monkeypatch):
    server = Server({'Shared/reports': {1: REPORT}, 'INBOX/dmarc': {1: REPORT}})
    real_select = server.select

    def select(mailbox, readonly=False):
        if 'Shared' in mailbox:
            raise imaplib.IMAP4.readonly('Shared/reports is not writable')
        return real_select(mailbox, readonly)
    monkeypatch.setattr(server, 'select', select)
    result, processed, *_ = _run(monkeypatch, server, '["Shared/reports","INBOX/dmarc"]')
    assert processed == [('INBOX/dmarc', '1')]
    assert result['status'] == 'error' and result['error_message'] == 'Failed to select folder Shared/reports'
