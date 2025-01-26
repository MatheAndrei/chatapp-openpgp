from enum import Enum


class ServerEvent(Enum):
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    MESSAGE = "message"
