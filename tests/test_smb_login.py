"""Regression tests for SMBClient.login() guest/null-session fallback.

The fallback used to authenticate successfully but still return False, so a
working guest or null session was reported as "Unable to login". These tests
mock impacket's SMBConnection so no real server is needed.
"""

import pytest

import snaffcore.smb as smb


class FakeConn:
    """Stand-in for impacket SMBConnection with a configurable accept rule."""

    def __init__(self, *args, **kwargs):
        pass

    def login(self, user, password, domain='', lmhash='', nthash=''):
        if not FakeConn.accepts(user, password):
            raise Exception('STATUS_LOGON_FAILURE')
        # success -> return normally


def make_client(monkeypatch, accepts, username, password=''):
    FakeConn.accepts = staticmethod(accepts)
    monkeypatch.setattr(smb, 'SMBConnection', FakeConn)
    return smb.SMBClient('127.0.0.1', username, password, '', '', None)


def test_guest_fallback_reports_success(monkeypatch):
    # Server accepts only the Guest account.
    client = make_client(monkeypatch,
                         lambda u, p: u == 'Guest', username='Guest')
    assert client.login() is True


def test_null_session_fallback_reports_success(monkeypatch):
    # Server accepts only an empty (null) user, after guest fails.
    client = make_client(monkeypatch,
                         lambda u, p: u == '', username='alice', password='bad')
    assert client.login() is True


def test_all_attempts_fail_returns_false(monkeypatch):
    client = make_client(monkeypatch,
                         lambda u, p: False, username='alice', password='bad')
    assert client.login() is False


def test_valid_credentials_succeed(monkeypatch):
    client = make_client(monkeypatch,
                         lambda u, p: (u, p) == ('alice', 'secret'),
                         username='alice', password='secret')
    assert client.login() is True
