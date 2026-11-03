"""Crawl-level tests for snaffle_directory/process_file using a mocked SMB
client, covering the --no-download and default behaviours."""

import os
import shutil

import pytest

from snaffcore.classifier import Rules
import snaffcore.go_snaffle as g


class Entry:
    """Mimics impacket SharedFile for directory listings."""

    def __init__(self, name, is_dir=False, size=100):
        self._n, self._d, self._s = name, is_dir, size

    def get_longname(self):
        return self._n

    def is_directory(self):
        return self._d

    def get_filesize(self):
        return self._s


def make_client(tree, downloaded):
    class FakeConn:
        def getFile(self, share, name, callback):
            downloaded.append(name)
            callback(b'password = "secret123"')

    class FakeClient:
        conn = FakeConn()

        def ls(self, share, path):
            for e in tree.get(path, []):
                yield e

    return FakeClient()


class Opts:
    def __init__(self, no_download=False, go_loud=False, max_file_snaffle=10000):
        self.no_download = no_download
        self.go_loud = go_loud
        self.max_file_snaffle = max_file_snaffle


@pytest.fixture(scope="module")
def rules():
    r = Rules()
    r.prepare_classifiers()
    return r


@pytest.fixture(autouse=True)
def _clean_remotefiles():
    shutil.rmtree("remotefiles", ignore_errors=True)
    yield
    shutil.rmtree("remotefiles", ignore_errors=True)


TREE = {
    "": [Entry("Users", is_dir=True), Entry("secret.ppk"), Entry("photo.jpg")],
    "Users": [Entry("web.config", size=50)],
}


def test_no_download_writes_nothing(rules):
    downloaded = []
    client = make_client(TREE, downloaded)
    g.snaffle_directory(client, "C$", "", "10.0.0.9", rules, Opts(no_download=True))
    assert downloaded == []
    assert not os.path.exists("remotefiles")


def test_default_downloads_matches_only(rules):
    downloaded = []
    client = make_client(TREE, downloaded)
    g.snaffle_directory(client, "C$", "", "10.0.0.9", rules, Opts())
    # secret.ppk (name match) and web.config (relay->content match) get fetched;
    # photo.jpg is discarded by extension and never downloaded.
    assert any(d.endswith("secret.ppk") for d in downloaded)
    assert any(d.endswith("web.config") for d in downloaded)
    assert not any("photo.jpg" in d for d in downloaded)


def test_directory_discard_prevents_recursion(rules):
    downloaded = []
    tree = {
        "": [Entry("Windows", is_dir=True)],
        "Windows": [Entry("system32", is_dir=True)],
        "Windows\\system32": [Entry("evil.ppk")],
    }
    client = make_client(tree, downloaded)
    g.snaffle_directory(client, "C$", "", "10.0.0.9", rules, Opts())
    assert downloaded == []  # system32 is discarded, never descended into
