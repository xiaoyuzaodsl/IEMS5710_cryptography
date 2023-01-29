import socket
#certificate request
from OpenSSL import crypto, SSL
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from os.path import join
import random
import os
from base64 import b64encode
import hashlib, hmac, binascii
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

iv  = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
my_id = sys.argv[1]
CN_stu = sys.argv[1]
k = crypto.PKey()
k.generate_key(crypto.TYPE_RSA,2048)
#create a CSR file
req = crypto.X509Req()
req.get_subject().C = "CN" #country
req.get_subject().ST = "HK" #state
req.get_subject().L = "HK" #location,means city
req.get_subject().O = "CUHK" #oganization
req.get_subject().OU = "CUHK" #organization unit
req.get_subject().CN = CN_stu #comman name
req.set_pubkey(k)
req.sign(k, 'sha512')
key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

s1 = socket.socket()
s1.connect(('127.0.0.1',3000))
# send CUHK CSR and wait for the certificate
# s1.send(str(my_id).encode('utf-8'))
# s1.recv(2048)
send_data = csr
s1.send(send_data)
recv_certs = s1.recv(2048)
print(CN_stu," sign finished")
print("revceive my cert from CUHK as following:\n{}".format(recv_certs.decode()))
mycert = crypto.load_certificate(crypto.FILETYPE_PEM, recv_certs)
# print("cert issuer:{}".format(mycert.get_issuer()))
# print("cert subject:{}".format(mycert.get_subject()))
s1.close()

# send cert to blackboard
s2 = socket.socket()
s2.connect(('127.0.0.2',4000))
stu_certificate=crypto.dump_certificate(crypto.FILETYPE_PEM,mycert)
s2.send(stu_certificate)

# directly from the blackboard recv the session key, just test
# msg = s2.recv(2048)
# session_key = msg.decode()
# session_key_bytes = bytes(session_key, encoding="raw_unicode_escape")
# print("I receive session key:",session_key_bytes)
# s2.send(b'get the session key')

# see the line 31, can also use "key" variable to be private key
private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
private_key_rsa = RSA.import_key(private_key)
#print("private:{}\n".format(private_key_rsa.exportKey()))
decryptor = PKCS1_OAEP.new(private_key_rsa)

# public_key_cert = mycert.get_pubkey()
# public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, k)
# public_key_rsa = RSA.import_key(public_key)
# print("public:{}\n".format(public_key_rsa.exportKey()))
# public_key2 = crypto.dump_publickey(crypto.FILETYPE_PEM, public_key_cert)
# public_key2_rsa = RSA.import_key(public_key2)
# encryptor = PKCS1_OAEP.new(public_key_rsa)
#
# encrypted = encryptor.encrypt(msg)
# decrypt = decryptor.decrypt(encrypted)
# print("decrpyt---------:",decrypt)


msg = s2.recv(4096)
decryptor = PKCS1_OAEP.new(private_key_rsa)
decrypted = decryptor.decrypt(msg)
print('Decrypted session key:', decrypted)

session_key_bytes = decrypted
#now I will send encryption and MAC seperately
final_msg = "This is submission from " + CN_stu + "\n"
cipher_gcm = AES.new(session_key_bytes,AES.MODE_GCM,iv)
cipher_gcm.update(b'header')
ciphertext = bytearray(cipher_gcm.encrypt(bytearray(final_msg, encoding='utf-8')))
print("I send ciphertext:{}".format(ciphertext.hex()))
s2.send(ciphertext)
#simple send and receive to avoid the two send be received together
s2.recv(2048)
tagMAC = cipher_gcm.digest()
s2.send(tagMAC)
print("I send MAC:{}".format(tagMAC))

s2.close()