"""Offline tests for the impacket-based LDAP functions in go_snaffle.

These cover the signing-aware bind fallback (ldap:// -> ldaps://, real creds ->
anonymous), pass-the-hash wiring, and parsing of dNSHostName out of impacket's
ldapasn1 search results. impacket's LDAPConnection is mocked so no DC is needed.
"""

import pytest

import snaffcore.go_snaffle as g
from impacket.ldap.ldap import LDAPSessionError


class FakeLDAPConnection:
    """Stand-in for impacket LDAPConnection with a configurable accept rule.

    `accepts(url, user, password, nthash)` decides whether login() succeeds.
    Every constructed instance and login attempt is recorded on the class.
    """

    attempts = []
    accepts = staticmethod(lambda url, user, pw, nt: True)
    search_results = []

    def __init__(self, url, baseDN='', dstIp=None, **kwargs):
        self.url = url
        self.baseDN = baseDN

    def login(self, user='', password='', domain='', lmhash='', nthash=''):
        FakeLDAPConnection.attempts.append(
            {'url': self.url, 'user': user, 'password': password,
             'domain': domain, 'nthash': nthash})
        if not FakeLDAPConnection.accepts(self.url, user, password, nthash):
            raise LDAPSessionError(errorString='STATUS_LOGON_FAILURE')

    def search(self, **kwargs):
        return FakeLDAPConnection.search_results


@pytest.fixture(autouse=True)
def _patch(monkeypatch):
    FakeLDAPConnection.attempts = []
    FakeLDAPConnection.accepts = staticmethod(lambda url, user, pw, nt: True)
    FakeLDAPConnection.search_results = []
    monkeypatch.setattr(g.ldap_impacket, 'LDAPConnection', FakeLDAPConnection)
    yield


def test_bind_succeeds_over_plain_ldap_first():
    conn = g.access_ldap_server('10.0.0.1', 'alice', 'pw', 'corp.local')
    assert isinstance(conn, FakeLDAPConnection)
    # First successful attempt should be plaintext ldap:// (signing works on 389).
    assert FakeLDAPConnection.attempts[0]['url'] == 'ldap://10.0.0.1'
    assert FakeLDAPConnection.attempts[0]['user'] == 'alice'


def test_passthehash_is_forwarded():
    g.access_ldap_server('10.0.0.1', 'alice', '', 'corp.local', nthash='aabbcc')
    assert FakeLDAPConnection.attempts[0]['nthash'] == 'aabbcc'


def test_falls_back_to_ldaps_then_anonymous():
    # Reject everything except an anonymous bind over ldaps:// (channel binding).
    FakeLDAPConnection.accepts = staticmethod(
        lambda url, user, pw, nt: url.startswith('ldaps') and user == '')
    conn = g.access_ldap_server('10.0.0.1', 'alice', 'pw', 'corp.local')
    assert isinstance(conn, FakeLDAPConnection)
    # ldap:// (creds, then anon) tried before ldaps:// finally accepts anon.
    tried = [(a['url'], a['user']) for a in FakeLDAPConnection.attempts]
    assert ('ldap://10.0.0.1', 'alice') in tried
    assert tried[-1] == ('ldaps://10.0.0.1', '')


def test_bind_returns_none_when_all_fail():
    FakeLDAPConnection.accepts = staticmethod(lambda *a: False)
    assert g.access_ldap_server('10.0.0.1', 'alice', 'pw', 'corp.local') is None


# --- list_computers parsing ---------------------------------------------------

class _Attr(dict):
    """Mimic an ldapasn1 attribute: supports attr['type'] / attr['vals']."""


def _entry(dnshostname):
    # Build an object that is an instance of ldapasn1.SearchResultEntry so the
    # isinstance() filter in list_computers accepts it.
    entry = g.ldapasn1.SearchResultEntry()
    entry._fake_attrs = [_Attr(type='dNSHostName', vals=[dnshostname])]
    return entry


def test_list_computers_extracts_dnshostnames(monkeypatch):
    entries = [_entry('dc01.corp.local'), _entry('srv02.corp.local')]
    # non-entry items (e.g. referrals) must be skipped
    entries.insert(1, object())

    # Patch __getitem__ so entry['attributes'] returns our fake attribute list.
    monkeypatch.setattr(
        g.ldapasn1.SearchResultEntry, '__getitem__',
        lambda self, key: self._fake_attrs if key == 'attributes' else None,
        raising=False)

    FakeLDAPConnection.search_results = entries
    conn = FakeLDAPConnection('ldap://x')
    names = g.list_computers(conn, 'corp.local')
    assert names == ['dc01.corp.local', 'srv02.corp.local']
