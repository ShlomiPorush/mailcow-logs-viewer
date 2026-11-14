"""The suppression list search is literal, and finds a domain or pattern
block by its value without the backslashes it is stored with."""
from test_rspamd_two_way import MARK, _add, db  # noqa: F401  db is a fixture


def _found(db, text):
    from app.routers.suppressions import list_suppressions
    with db() as s:
        result = list_suppressions(db=s, page=1, per_page=200, search=text, type_filter=None, reason_filter=None,
                                   active_filter=None, sort_by='created_at', sort_dir='desc')
    return {item['email'] for item in result['items']}


def test_a_domain_block_is_found_by_its_domain_and_by_its_own_value(db):
    domain = f'/^.+@d{MARK}\\.example$/i'
    _add(db, domain)
    _add(db, f'someone@d{MARK}xexample.test')
    assert domain in _found(db, f'd{MARK}.example')
    assert _found(db, domain) == {domain}, 'its own value finds it, and only it'


def test_percent_and_underscore_are_themselves(db):
    _add(db, f'a_b{MARK}@example.test')
    _add(db, f'axb{MARK}@example.test')
    assert _found(db, f'a_b{MARK}') == {f'a_b{MARK}@example.test'}
    assert _found(db, f'a%b{MARK}') == set()
