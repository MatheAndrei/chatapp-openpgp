import struct
import socket
import select
import ipaddress
import threading
from typing import List, Tuple, Dict, Callable, Any

from .client import Client
from .server_events import ServerEvent
from pgp.crypto import RSA, RSAPublicKey, RSAPrivateKey, OpenPGP


def _send(s: socket.socket, data: str | bytes):
    if not isinstance(data, bytes):
        data = data.encode("utf-8")
    data = struct.pack(">I", len(data)) + data
    print(f"Data: {data}")
    s.sendall(data)


def _recv_bytes(s: socket.socket, n: int) -> bytes | None:
    data = bytearray()
    while len(data) < n:
        part = s.recv(n - len(data))
        if not part:
            return None
        data.extend(part)
    return bytes(data)


def _recv(s: socket.socket) -> bytes | None:
    data_len = _recv_bytes(s, 4)
    if not data_len:
        return None

    data_len = struct.unpack(">I", data_len)[0]

    data = _recv_bytes(s, data_len)
    if not data:
        return None

    return data


class Server:
    def __init__(self):
        self.clients: Dict[Tuple[str, int], Tuple[socket.socket, Client]] = {}
        self.subs: Dict[ServerEvent, List[Callable]] = {
            ServerEvent.CONNECT: [],
            ServerEvent.DISCONNECT: [],
            ServerEvent.MESSAGE: []
        }

        # generate public & private keys
        private_key, public_key = RSA.generate_keys()
        self.public_key: RSAPublicKey = public_key
        self.private_key: RSAPrivateKey = private_key

        # create server socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('', 0))

        # create fds to listen
        self.read_fds = [self.socket]
        self.write_fds = []
        self.exception_fds = [self.socket]

        # get server host & port
        self.host, self.port = self.socket.getsockname()

        # create thread for server
        self.thread = threading.Thread(target=self._work, daemon=True)

    def run(self):
        self.socket.listen(5)
        self.thread.start()

        print(f"Server running at ({self.host}, {self.port})")

    def _work(self):
        while True:
            ready_to_read, _, in_error = select.select(self.read_fds, self.write_fds, self.exception_fds, 1)

            # handle sockets
            for s in ready_to_read:
                # open connection
                if s is self.socket:
                    conn, addr = self.socket.accept()
                    self._open_connection(conn)
                    continue

                # read data
                try:
                    data = _recv(s)
                    if data:
                        print(f"Received message from {s.getpeername()}")

                        # get client
                        client = self.clients[s.getpeername()][1]

                        # decompose data
                        data = OpenPGP.decompose_message(data, self.private_key, client.public_key)
                        if not data:
                            continue

                        # notify
                        self._notify(ServerEvent.MESSAGE, client, data)
                    else:
                        self._close_connection(s)
                except Exception as e:
                    print(f"Error occurred while handling client {s.getpeername()}: {str(e)}")
                    self._close_connection(s)

            # handle errors
            for s in in_error:
                print(f"Exception on socket: {s.getpeername()}")
                self._close_connection(s)

    def _open_connection(self, s: socket.socket):
        # create client
        addr = s.getpeername()

        # send my public key
        _send(s, RSA.serialize_public_key(self.public_key))

        # receive their public key
        client_public_key = RSA.deserialize_public_key(_recv(s))

        # create client
        client = Client(addr[0], addr[1], client_public_key, None)

        # register client
        self.clients[addr] = (s, client)
        self.read_fds.append(s)
        self.exception_fds.append(s)

        print(f"Connected with {addr}")

        # notify
        self._notify(ServerEvent.CONNECT, client)

    def _close_connection(self, s: socket.socket):
        addr = s.getpeername()

        # notify
        self._notify(ServerEvent.DISCONNECT, self.clients[addr][1])

        print(f"Disconnected from {addr}")

        # remove client
        self.clients.pop(addr, None)
        self.read_fds.remove(s)
        self.exception_fds.remove(s)
        s.close()

    def _notify(self, event: ServerEvent, client: Client, data: Any | None = None):
        for callback in self.subs[event]:
            callback(client, data)

    def subscribe(self, event: ServerEvent, callback: Callable):
        self.subs[event].append(callback)

    def connect(self, host: str, port: int):
        # resolve host
        try:
            ipaddress.ip_address(host)
        except ValueError:
            try:
                host = socket.gethostbyname(host)
            except socket.gaierror:
                return

        # skip if connecting to self
        if ipaddress.ip_address(host).is_loopback and port == self.port:
            return

        # skip if already connected
        if (host, port) in self.clients:
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            self._open_connection(s)
        except ConnectionRefusedError:
            pass

    def send(self, client: Client, data: Any):
        # get client's socket
        s = self.clients[(client.host, client.port)][0]

        print(f"Plain data: {data}")

        # compose message
        data = OpenPGP.compose_message(data, client.public_key, self.private_key)

        # send message
        _send(s, data)

        print(f"Sent message to ({client.host}, {client.port})")

    def recv(self, client: Client) -> str:
        # get client's socket
        s = self.clients[(client.host, client.port)][0]

        # read data
        data = _recv(s)
        if not data:
            self._close_connection(s)

        print(f"Received message from ({client.host}, {client.port})")

        # decompose data
        data = OpenPGP.decompose_message(data, self.private_key, client.public_key)
        if not data:
            return None

        return data
