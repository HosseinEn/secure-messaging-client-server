import hashlib
import socket
import threading
import math
from Crypto.Cipher import AES
from Crypto.Util import Counter
import RSA
import elgamal

HOST = '127.0.0.1'
PORT = 3000
public_key = None
shared_key = None
private_key  = None
exchange_mode = None

IV = 10


def decrypt_key(value):
    global private_key, exchange_mode

    if exchange_mode == 'ElGamal':
        return elgamal.decrypt(private_key, value)
    elif exchange_mode == 'RSA':
        return RSA.rsa_decrypt(private_key, int(value))


def generate_pub_priv_key():
    global exchange_mode

    if exchange_mode == 'ElGamal':
        return elgamal.generate_keys()
    elif exchange_mode == 'DH':
        # TODO implement DH
        pass
    elif exchange_mode == 'RSA':
        return RSA.rsa_generate_key(113, 23)


def handle_client(client_socket):
    global public_key, shared_key, private_key, exchange_mode

    client_address = client_socket.getpeername()
    data = client_socket.recv(1024).decode('utf-8')
    ctrl, value = data.split("@", 1)
    exchange_mode = value
    (private_key, public_key) = generate_pub_priv_key()
    data = f'public_key@{public_key}'
    client_socket.send(str(data).encode('utf-8'))
    data = client_socket.recv(1024).decode('utf-8')
    ctrl, value = data.split("@", 1)
    shared_key = decrypt_key(value)    
    print ('Ready for secure communication!')
    
    while True:
        data = client_socket.recv(1024)

        if not data:
            print(client_address, " exited! Ready for new connections...")
            break

        hexIV = hex(IV)[2:8].zfill(16)
        encobj = AES.new(hashlib.sha256(str(shared_key).encode()).digest(), AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(hexIV.encode(), byteorder='big')))
        plaintext = encobj.decrypt(data)
        print("Received data: ", data)
        print("Decrypted msg in server: ", plaintext.decode())    
        msg = input('Enter your message: ')
        hexIV = hex(IV)[2:8].zfill(16)
        encobj = AES.new(hashlib.sha256(str(shared_key).encode()).digest(), AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(hexIV.encode(), byteorder='big')))
        encrypted_msg = encobj.encrypt(msg.encode())
        client_socket.send(encrypted_msg)




server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((HOST, PORT))
server_socket.listen(5)

print("Server is listening on port 3000...")

client_list = []

while True:
    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")
    client_list.append(client_socket)
    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()
