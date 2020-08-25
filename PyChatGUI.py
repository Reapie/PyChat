from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import QObject, QRunnable, QThread, pyqtSlot, pyqtSignal
import socket
import threading
import time
import sys
import os
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
nick = "Anon"
connected = False
waiting = False

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

def send(message):
    if not message.startswith("!"):
        message = "!msg " + nick + ": " + message
    message = "!chn " + password + " " + encrypt(message.encode()).decode()
    broadcast_send.sendto(message.encode(), ('<broadcast>', PORT))

class Worker1(QtCore.QObject):
    message  = QtCore.pyqtSignal(str)
    #Worker Thread
    def __init__(self):
        QtCore.QObject.__init__(self)

    def run(self):
        global wanted_nick, nick, waiting
        while True:
            if connected:
                data = broadcast_recv.recv(SIZE)
                if not data.startswith(b"!chn " + password.encode() + b" "):
                    continue
                else:
                    data = decrypt(data[6 + len(password):]).decode()
                #Decrypted and ready to compute
                if data.startswith("!verify ") and str(data[8:].strip()) == nick and nick != "Anon" and not waiting:
                    send("!unavaliable " + nick)
                if data.startswith("!unavaliable ") and str(data[13:].strip()) == wanted_nick and waiting:
                    self.message.emit("<i>The Nickname you chose is already in use</i>")
                    wanted_nick = ""
                if data.startswith("!msg "):
                    self.message.emit(data[5:])


class Worker2(QtCore.QObject):
    #Worker Thread
    def __init__(self):
        QtCore.QObject.__init__(self)
    
    def run(self):
        global waiting
        time.sleep(1)
        waiting = False


class Ui_MainWindow(QtWidgets.QWidget):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(400, 400)
        MainWindow.setFixedSize(MainWindow.size())
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(10)
        MainWindow.setFont(font)
        MainWindow.setStyleSheet("") 
        #MainWindow.setWindowIcon(QtGui.QIcon('icon.png')) Uncomment if you have a icon.png File
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.txtInPwd = QtWidgets.QLineEdit(self.centralwidget)
        self.txtInPwd.setGeometry(QtCore.QRect(10, 10, 181, 23))
        self.txtInPwd.setObjectName("txtInPwd")
        self.btnConnect = QtWidgets.QPushButton(self.centralwidget)
        self.btnConnect.setGeometry(QtCore.QRect(200, 10, 91, 23))
        self.btnConnect.setObjectName("btnConnect")
        self.btnDisconnect = QtWidgets.QPushButton(self.centralwidget)
        self.btnDisconnect.setEnabled(False)
        self.btnDisconnect.setGeometry(QtCore.QRect(300, 10, 91, 23))
        self.btnDisconnect.setObjectName("btnDisconnect")
        self.txtOut = QtWidgets.QTextBrowser(self.centralwidget)
        self.txtOut.setGeometry(QtCore.QRect(10, 40, 381, 321))
        self.txtOut.setObjectName("txtOut")
        self.txtInMsg = QtWidgets.QLineEdit(self.centralwidget)
        self.txtInMsg.setGeometry(QtCore.QRect(10, 370, 281, 23))
        self.txtInMsg.setObjectName("txtInMsg")
        self.btnSend = QtWidgets.QPushButton(self.centralwidget)
        self.btnSend.setGeometry(QtCore.QRect(300, 370, 91, 23))
        self.btnSend.setObjectName("btnSend")
        self.btnSend.setEnabled(False)
        MainWindow.setCentralWidget(self.centralwidget)
        self.btnSend.clicked.connect(self.send_btn)
        self.txtInMsg.returnPressed.connect(self.send_btn)
        self.txtInPwd.returnPressed.connect(self.connect_btn)
        self.btnConnect.clicked.connect(self.connect_btn)
        self.btnDisconnect.clicked.connect(self.disconnect_btn)
        self.timer = QtCore.QTimer(self)
        self.timer.setSingleShot(True)
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "PyChat"))
        self.txtInPwd.setPlaceholderText(_translate("MainWindow", "Password"))
        self.txtInMsg.setPlaceholderText(_translate("MainWindow", "Your Message"))
        self.btnConnect.setText(_translate("MainWindow", "Connect"))
        self.btnDisconnect.setText(_translate("MainWindow", "Disconnect"))
        self.btnSend.setText(_translate("MainWindow", "Send"))
    
    def init(self):
        self.server = QThread()
        self.worker = Worker1()
        self.worker.message.connect(self.display_msg)
        self.worker.moveToThread(self.server)
        self.server.started.connect(self.worker.run)
        self.server.start()


    def getText(self):
        text, okPressed = QtWidgets.QInputDialog.getText(self, "Username", "Unique Username: ")
        if okPressed and text.strip() != '':
            return text

    def display_msg(self, message):
        self.txtOut.append(message)

    def verify(self):
        global wanted_nick, nick, waiting
        wanted_nick = self.getText()
        if nick != wanted_nick and wanted_nick != "":
            self.waiter = QThread(parent=self)
            self.sleeper = Worker2()
            self.sleeper.moveToThread(self.waiter)
            self.waiter.started.connect(self.sleeper.run)
            send("!verify " + wanted_nick)
            self.waiter.start()
            waiting = True
            while waiting:
                app.processEvents()
            if wanted_nick == "":
                self.verify()
            else:
                nick = wanted_nick
                self.addText("<i>You have been verifed</i>")

    def addText(self, text):
        self.txtOut.append(text)
    
    def send_btn(self):
        send(self.txtInMsg.text())
        self.txtInMsg.clear()

    def connect_btn(self):
        global connected, wanted_nick
        self.txtInPwd.setEnabled(False)
        self.password = self.txtInPwd.text()
        self.btnSend.setEnabled(True)
        self.btnConnect.setEnabled(False)
        self.btnDisconnect.setEnabled(True)
        connected = True
        self.verify()

    def disconnect_btn(self):
        global connected
        self.txtInPwd.setEnabled(True)
        self.password = ""
        self.btnSend.setEnabled(False)
        self.btnConnect.setEnabled(True)
        self.btnDisconnect.setEnabled(False)
        self.txtOut.clear()
        connected = False


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    ui.init()
    sys.exit(app.exec_())