# https://asecuritysite.com/encryption/aes_modes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import hashlib
import binascii
import Padding
import numpy as np







DATA_TYPE = 'PDF' # PDF, text can also be used as data for encryption and decryption
PDF_FILE = 'test.pdf'
PASSWORD = 'hello'
INPUT_INITIAL_VALUE = 10





def encrypt(plaintext, key, mode):
    encobj = AES.new(key, mode)
    return (encobj.encrypt(plaintext))


def decrypt(ciphertext, key, mode):
    encobj = AES.new(key, mode)
    return (encobj.decrypt(ciphertext))


def encryptWithIV(plaintext, key, mode, iv):
    encobj = AES.new(key, mode, iv)
    return (encobj.encrypt(plaintext))


def decryptWithIV(ciphertext, key, mode, iv):
    encobj = AES.new(key, mode, iv)
    return (encobj.decrypt(ciphertext))


def encryptWithCTR(plaintext, key, mode, ctr):
    encobj = AES.new(key, mode, counter=ctr)
    return (encobj.encrypt(plaintext))


def decryptWithCTR(ciphertext, key, mode, ctr):
    encobj = AES.new(key, mode, counter=ctr)
    return (encobj.decrypt(ciphertext))


def hexOfPlainText(plaintext):
	return binascii.hexlify(plaintext.encode()).decode()


def hexOfCiphertext(ciphertext):
     return binascii.hexlify(bytearray(ciphertext)).decode()


def padData(data, aesMode):
	if DATA_TYPE == 'PDF':
		if aesMode == AES.MODE_CTR:
			return data
		paddedData = pad(data, Padding.AES_blocksize)
	else:
		paddedData = Padding.appendPadding(data, blocksize=Padding.AES_blocksize, mode=0).encode()
	return paddedData


def get_counter():
	return Counter.new(128, initial_value=int.from_bytes(IV.encode(), byteorder='big'))


def unpadData(data, aesMode):
	if DATA_TYPE == 'PDF':
		if aesMode == AES.MODE_CTR:
			return data
		unpaddedData = unpad(data, Padding.AES_blocksize)
	else:
		unpaddedData = Padding.removePadding(data.decode(), mode=0)
	return unpaddedData


def pp(text, color):
	if color == "DG":
		return f"\033[1;30;40m{text}\033[0m"
	elif color == "B":
		return f"\033[0;37;41m{text}\033[0m"
	elif color == "BG":
		return f"\033[1;31;40m{text}\033[0m"
	elif color == "BM":
		return f"\033[0;37;46m{text}\033[0m"
	

def show_ciphertext(ciphertext):
	print(pp(f"truncated ciphertext with IV {IV}: ", "DG") + (str(ciphertext)[1:200] if DATA_TYPE == 'PDF'
			else str(ciphertext)))


def show_plaintext(plaintext):
	print(pp("plaintext: ", "BG") + (str(plaintext)[1:200] if DATA_TYPE == 'PDF'
			else str(plaintext)))


def show_decrypt(plaintext):
		print(pp("truncated decrypt: ", "B") + (str(plaintext)[1:200] if DATA_TYPE == 'PDF'
		 else str(plaintext)))


def getPDF(name):
	file = open(name, "rb")
	data = file.read()
	file.close()
	return data


def createPDF(name, data):
	file = open(name, "wb")
	data = file.write(data)
	file.close()


def buildAESKey(key):
	return hashlib.sha256(key.encode()).digest()


def buildIV(initialValue):
	return hex(initialValue)[2:8].zfill(16)


def perform(value, aesMode, IV=None):
	plaintext = padData(value, aesMode)
	show_plaintext(plaintext)
	
	if aesMode in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
		ciphertext = encryptWithIV(plaintext, key, aesMode, IV.encode())
		show_ciphertext(ciphertext)
		plaintext = decryptWithIV(ciphertext, key, aesMode, IV.encode())
	elif aesMode == AES.MODE_CTR:
		ciphertext = encryptWithCTR(plaintext, key, aesMode, get_counter())
		show_ciphertext(ciphertext)
		plaintext = decryptWithCTR(ciphertext, key, aesMode, get_counter())
	else:
		ciphertext = encrypt(plaintext, key, aesMode)
		show_ciphertext(ciphertext)
		plaintext = decrypt(ciphertext, key, aesMode)

	plaintext = unpadData(plaintext, aesMode)         

	show_decrypt(plaintext)
	print()
	
	return plaintext




# if __name__ == "__main__":

# 	value = 'osijfio'
# 	key = buildAESKey(PASSWORD)
# 	data = getPDF(PDF_FILE)
# 	IV = buildIV(INPUT_INITIAL_VALUE)


# 	# perform(value, AES.MODE_ECB)
# 	# perform(value, AES.MODE_CBC, IV)
# 	# perform(value, AES.MODE_CFB, IV)
# 	# perform(value, AES.MODE_OFB, IV)

# 	print(pp("AES CBC encryption and decryption mode:", "BM"))
# 	createPDF('cbc.pdf', perform(data, AES.MODE_CBC, IV))
# 	print(pp("AES CTR encryption and decryption mode:", "BM"))
# 	createPDF('ctr.pdf', perform(data, AES.MODE_CTR, IV))
	