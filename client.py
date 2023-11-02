import hashlib
import socket
import ast
import RSA
from Crypto.Util import Counter
from Crypto.Cipher import AES

HOST = '127.0.0.1'
PORT = 3000
SHARED_KEY = 22
IV = 10

# Maybe we should exchange IV too!!!



def elgamal_generate():
    pass

def dh_generate():
    pass

def rsa_generate():
    pass

def encrypt_key(mode: str):
    global public_key

    if mode == 'RSA':
        return RSA.rsa_encrypt(public_key, SHARED_KEY)


def rcv_encrypted_msg():
    while True:
        data = client_socket.recv(1024).decode('utf-8')
        if not data:
            break
        print(data)

def send_encrypted_msg():
    while True:
        msg = input()
        client_socket.send(msg.encode('utf-8'))

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = (HOST, PORT)

client_socket.connect(server_address)        

message = 'key_exchange_mode@RSA'
# message = 'key_exchange_mode@ElGamal'
# message = 'key_exchange_mode@DH'

client_socket.send(message.encode('utf-8'))

response = client_socket.recv(1024).decode('utf-8')


public_key = ast.literal_eval(response.split("@", 1)[1])



C = encrypt_key('RSA')
data = f'shared_key@{C}'
client_socket.send(data.encode('utf-8'))


while True:
    print ('Ready for secure communication!')

    msg = input('Enter your message: ')
    hexIV = hex(IV)[2:8].zfill(16)

    encobj = AES.new(hashlib.sha256(str(SHARED_KEY).encode()).digest(), AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(hexIV.encode(), byteorder='big')))
    encrypted_msg = encobj.encrypt(msg.encode())
    client_socket.send(encrypted_msg)

    data = client_socket.recv(1024)

    if not data:
        break

    hexIV = hex(IV)[2:8].zfill(16)
    encobj = AES.new(hashlib.sha256(str(SHARED_KEY).encode()).digest(), AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(hexIV.encode(), byteorder='big')))
    plaintext = encobj.decrypt(data)
    print("Received data: ", data)
    print("Decrypted msg in server: ", plaintext.decode())

