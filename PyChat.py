import socket
import threading
import time
import sys
import base64
from cryptography import fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password = ""
PORT = 42069
SIZE = 1024 * 5
wanted_nick = ""
nick = ""

broadcast_send = socket.socket(
    socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
broadcast_send.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
broadcast_send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

broadcast_recv = socket.socket(
    socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
broadcast_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
broadcast_recv.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
broadcast_recv.bind(("", PORT))


def get_key():
    key = password.encode()
    salt = b"[R8b\x7f\xd2\xd1s\x975\x17\xd1\xd7\xf3\xdd\xd2"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(key))


def encrypt(data):
    fernet = Fernet(get_key())
    return fernet.encrypt(data)


def decrypt(data):
    fernet = Fernet(get_key())
    return fernet.decrypt(data)


def listen():
    global wanted_nick, nick
    while True:
        data = broadcast_recv.recv(SIZE).decode()
        if not data.startswith("!chn " + str(hash(password)) +" "):
            continue
        else:
            data = data.encode()
            data = decrypt(data[6 + len(str(hash(password))):]).decode()
        #Decrypted and ready to compute
        #print(data)
        if data.startswith("!verify ") and str(data[8:].strip()) == nick:
            send("!unavaliable " + nick)
            print("Somebody tied to use your nickname")
        elif data.startswith("!unavaliable ") and str(data[13:].strip()) == wanted_nick:
            wanted_nick = ""
        elif data.startswith("!msg "):
            print(data[5:])


#Block while not verified
def send(message):
    if not message.startswith("!"):
        message = "!msg " + nick + ": " + message
    message = "!chn " + str(hash(password)) + " " + encrypt(message.encode()).decode()
    broadcast_send.sendto(message.encode(), ('<broadcast>', PORT))


def verify():
    global wanted_nick, nick
    if nick != wanted_nick:
        send("!verify " + wanted_nick)
        time.sleep(1)
        if wanted_nick == "":
            wanted_nick = input("Your username is already in use, please enter a new one: ")
            verify()
        else:
            nick = wanted_nick
            print("You have been verified!")



if __name__ == '__main__':
    server = threading.Thread(target=listen)
    server.setDaemon(True)
    server.start()
    password = input("Please Enter Password: ").strip()
    wanted_nick = input("Please Enter Nickname: ").strip()
    verify()
    try:
        while True:
            send(input(nick + ": "))
            print("\r")
    except KeyboardInterrupt:
        exit()
