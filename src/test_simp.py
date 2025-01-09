# test_simp.py
import pytest
import socket
from src.simp_client import SIMPClient, create_datagram, parse_datagram
from src.simp_daemon import SIMPDaemon
import threading

@pytest.fixture
def client():
    return SIMPClient(client_ip='127.0.0.1', daemon_port=7777)

@pytest.fixture
def daemon():
    return SIMPDaemon(client_port=7778, daemon_port=7777, daemon_ip='127.0.0.1')

def test_create_datagram():
    datagram = create_datagram(0x01, 0x02, 0x00, 'user', 'payload')
    assert len(datagram) == 39 + len('payload')

def test_parse_datagram():
    datagram = create_datagram(0x01, 0x02, 0x00, 'user', 'payload')
    parsed = parse_datagram(datagram)
    assert parsed['type'] == 0x01
    assert parsed['operation'] == 0x02
    assert parsed['user'] == 'user'
    assert parsed['payload'] == 'payload'

def test_client_connect_to_daemon(client, daemon):
    daemon_thread = threading.Thread(target=daemon.start, daemon=True)
    daemon_thread.start()
    client.username = 'testuser'
    client.connect_to_daemon('127.0.0.1')
    assert client.connected_to_daemon

def test_client_initiate_chat_request(client, daemon):
    daemon_thread = threading.Thread(target=daemon.start, daemon=True)
    daemon_thread.start()
    client.username = 'testuser'
    client.connect_to_daemon('127.0.0.1')
    client.initiate_chat_request('127.0.0.1')
    assert client.chat_started

def test_client_send_message(client, daemon):
    daemon_thread = threading.Thread(target=daemon.start, daemon=True)
    daemon_thread.start()
    client.username = 'testuser'
    client.connect_to_daemon('127.0.0.1')
    client.initiate_chat_request('127.0.0.1')
    client.send_message('Hello')
    assert client.chat_started

def test_client_end_chat(client, daemon):
    daemon_thread = threading.Thread(target=daemon.start, daemon=True)
    daemon_thread.start()
    client.username = 'testuser'
    client.connect_to_daemon('127.0.0.1')
    client.initiate_chat_request('127.0.0.1')
    client.end_chat()
    assert not client.chat_started