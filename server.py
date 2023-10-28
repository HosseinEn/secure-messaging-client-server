import hashlib
import socket
import threading
import math
from Crypto.Cipher import AES
from Crypto.Util import Counter
import RSA

HOST = '127.0.0.1'
PORT = 3000
public_key = None
shared_key = None
private_key  = None
exchange_mode = None

IV = 10

def encrypt_msg():
    pass

def decrypt_msg():
    pass

def elgamal_generate():
    pass

def dh_generate():
    pass

def rsa_generate():
    p = 23
    q = 11
    n = p*q
    phi = (p-1)*(q-1)
    e = 2

    while(e<phi):
        if (math.gcd(e, phi) == 1):
            break
        else:
            e += 1
    
    k = 2
    d = ((k*phi)+1)/e
    # print("d =", d)
    # print(f'Public key: {e, n}')
    # print(f'Private key: {d, n}')
    return ({"d": d, "n": n}, {"e": e, "n": n})

def decrypt_key(value):
    global private_key

    # decryption
    # M = pow(int(float(value)), private_key['d'])
    # sk = math.fmod(M, private_key['n'])
    return RSA.rsa_decrypt(private_key, int(value))

def generate_pub_priv_key():
    global exchange_mode

    if exchange_mode == 'ElGamal':
        elgamal_generate()
    elif exchange_mode == 'DH':
        dh_generate()
    elif exchange_mode == 'RSA':
        return RSA.rsa_generate_key(113, 23)


# def encrypt_key(mode: str, shared_key):
#     global public_key

#     if mode == 'ElGamal':
#         c = elgamal_generate()
#     elif mode == 'DH':
#         c = dh_generate()
#     elif mode == 'RSA':
#         c = RSA.rsa_encrypt(public_key, shared_key)
#     return c

def process_request(client_socket, data):
    global public_key, shared_key, private_key, exchange_mode

    ctrl, value = data.split("@", 1)

    if ctrl == 'key_exchange_mode':
        exchange_mode = value
        (private_key, public_key) = generate_pub_priv_key(value)
        data = f'public_key:{public_key}'
        client_socket.send(str(public_key).encode('utf-8'))
       

    elif ctrl == 'msg':
        encobj = AES.new(shared_key, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(IV.encode(), byteorder='big')))
        encobj.decrypt(value)
    elif ctrl == 'shared_key':
        shared_key = decrypt_key(value)

def send_msg_to_client(msg):
    pass


def handle_client(client_socket):
    global public_key, shared_key, private_key, exchange_mode

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
