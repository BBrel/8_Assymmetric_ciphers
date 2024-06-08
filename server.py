import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class Server:
    def __init__(self, host='localhost', port=8889):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = host
        self.port = port
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)
        self.keys = RSA.generate(2048)
        self.cipher = PKCS1_OAEP.new(self.keys)  # класс для расшифровки в библиотеке Crypto

    def handle_client(self, client_socket):
        # Получение открытого ключа клиента
        client_pub_key_data = client_socket.recv(2048)
        client_pub_key = RSA.import_key(client_pub_key_data)
        client_cipher = PKCS1_OAEP.new(client_pub_key)

        # Отправка своего открытого ключа клиенту
        client_socket.send(self.keys.publickey().export_key())

        # Получение и расшифровка сообщения от клиента
        encrypted_msg = client_socket.recv(2048)
        print(f'Зашифрованное сообщение клиента: {encrypted_msg}')
        message = self.cipher.decrypt(encrypted_msg)
        print("расшифрованное сообщение от клиента:", message.decode())

        # Отправка обратного сообщения клиенту
        response = client_cipher.encrypt(b"hello client!")
        client_socket.send(response)

    def run(self):
        print("Сервер запущен и слушает на", self.host, self.port)
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Подключен клиент: {addr}")
            self.handle_client(client_socket)
            client_socket.close()


# Запуск сервера
server = Server()
server.run()
