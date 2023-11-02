import hashlib
import socket
import ast
import RSA
import elgamal
from Crypto.Util import Counter
from Crypto.Cipher import AES
from pp import pp

HOST = '127.0.0.1'
PORT = 3000
SHARED_KEY = 22
IV = 10

# Maybe we should exchange IV too!!!

def encrypt_key(mode: str):
    global public_key

    if mode == 'RSA':
        return RSA.rsa_encrypt(public_key, SHARED_KEY)
    elif mode == 'ElGamal':
        return elgamal.encrypt(public_key, SHARED_KEY)
    elif mode == 'DH':
        # TODO implement DH
        pass


def ex_mode(num):
    if num == '1':
        return 'RSA'
    elif num == '2':
        return 'ElGamal'
    elif num == '3':
        return 'DH'


EXCHANGE_MODE = ex_mode(input('Enter key exchange mode number: \n[1] RSA\n[2] ElGamal\n[3] DH\n\n'))

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (HOST, PORT)
client_socket.connect(server_address)        

message = f'key_exchange_mode@{EXCHANGE_MODE}'
# message = f'key_exchange_mode@{EXCHANGE_MODE}'
# message = f'key_exchange_mode@{EXCHANGE_MODE}'

client_socket.send(message.encode('utf-8'))
response = client_socket.recv(1024).decode('utf-8')
public_key = ast.literal_eval(response.split("@", 1)[1])



C = encrypt_key(EXCHANGE_MODE)
data = f'shared_key@{C}'
client_socket.send(data.encode('utf-8'))

print (pp(f'\nReady for secure communication using {EXCHANGE_MODE}!\n', 'BM'))

while True:

    msg = input(pp('\nEnter your message: ', 'C'))
    hexIV = hex(IV)[2:8].zfill(16)
    encobj = AES.new(hashlib.sha256(str(SHARED_KEY).encode()).digest(), AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(hexIV.encode(), byteorder='big')))
    encrypted_msg = encobj.encrypt(msg.encode())
    client_socket.send(encrypted_msg)
    print('Waiting for messages...')
    data = client_socket.recv(1024)

    if not data:
        break

    hexIV = hex(IV)[2:8].zfill(16)
    encobj = AES.new(hashlib.sha256(str(SHARED_KEY).encode()).digest(), AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(hexIV.encode(), byteorder='big')))
    plaintext = encobj.decrypt(data)
    print(pp('\nReceived data: ', 'BG'), data)
    print(pp('Decrypted msg in server: ', 'BG'), plaintext.decode())

