import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class Client:
    def __init__(self, host='localhost', port=8889):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = host
        self.port = port
        self.keys = RSA.generate(2048)
        self.cipher = PKCS1_OAEP.new(self.keys)  # класс для расшифровки в библиотеке Crypto

    def send_message(self):
        # Отправка открытого ключа серверу
        self.client_socket.send(self.keys.publickey().export_key())

        # Получение открытого ключа сервера
        server_pub_key_data = self.client_socket.recv(2048)
        server_pub_key = RSA.import_key(server_pub_key_data)
        server_cipher = PKCS1_OAEP.new(server_pub_key)

        # Шифровка и отправка сообщения
        encrypted_msg = server_cipher.encrypt(b"hello server!")
        self.client_socket.send(encrypted_msg)

        # Получение и расшифровка обратного сообщения от сервера
        encrypted_reply = self.client_socket.recv(2048)
        print(f'Зашифрованный ответ сервера: {encrypted_reply}')
        reply = self.cipher.decrypt(encrypted_reply)
        print("расшифрованный ответ от сервера:", reply.decode())

    def client_start(self):
        self.client_socket.connect((self.host, self.port))


# Запуск клиента
client = Client()
client.client_start()
client.send_message()
