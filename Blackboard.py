import socket
from OpenSSL import crypto, SSL
from os.path import join
import random
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from base64 import b64encode
import hashlib, hmac, binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

iv  = bytes.fromhex('000102030405060708090A0B0C0D0E0F')

socket_blackboard2cuhk = socket.socket()
socket_blackboard2cuhk.connect(('127.0.0.1', 3500))

stu2blackboard = socket.socket()
stu2blackboard.bind(('127.0.0.2',4000))
stu2blackboard.listen(10)
print("waiting for a student...")

while 1:
    sock_s1, addr_s1 = stu2blackboard.accept()
    #print(sock_s1, addr_s1)

    recv_msg = sock_s1.recv(2048)
    # print("\n-------receive message------\n{}".format(recv_msg.decode()))

    cert_from_cuhk = crypto.load_certificate(crypto.FILETYPE_PEM, recv_msg)
    cert_from_cuhk_bytes = crypto.dump_certificate(crypto.FILETYPE_PEM, cert_from_cuhk)

    # recv_id = socket_blackboard2cuhk.recv(2048)
    # socket_blackboard2cuhk.send('get the id'.encode('utf-8'))
    # print("id:{}".format(recv_id))
    recv_msg2 = socket_blackboard2cuhk.recv(2048)

    cert_from_stu = crypto.load_certificate(crypto.FILETYPE_PEM, recv_msg2)
    cert_from_stu_bytes = crypto.dump_certificate(crypto.FILETYPE_PEM, cert_from_stu)

    if cert_from_stu_bytes == cert_from_cuhk_bytes:
        print("\nthe sent cert is in the certs list")

        # directly send the session key to the stu, will noe used
        session_key_raw = os.urandom(16)
        session_key_bytes = binascii.hexlify(session_key_raw)
        print("we will send session key:{}".format(session_key_bytes))
        # sock_s1.send(session_key_bytes)
        # msg = sock_s1.recv(2048)
        # print("the session key get ot not:{}".format(msg))

        # encrypt a session key with the public key in cert
        # the encryption method we use rsa
        public_key_X509 = cert_from_stu.get_pubkey()
        public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, public_key_X509)
        public_key_rsa = RSA.import_key(public_key)
        # print("puclic key:",public_key_rsa.exportKey())
        msg = session_key_bytes
        encryptor = PKCS1_OAEP.new(public_key_rsa)
        encrypted = encryptor.encrypt(msg)
        # encrypted = binascii.hexlify(encrypted)
        # print("Encrypted session key:", encrypted)
        sock_s1.send(encrypted)

        # now I will use the receive key to generate a msg with MAC
        recv_msg = sock_s1.recv(2048)
        #print("recv msg:",recv_msg.hex())
        cipher_gcm = AES.new(session_key_bytes, AES.MODE_GCM, iv)
        cipher_gcm.update(b'header')
        plaintext = cipher_gcm.decrypt(recv_msg)
        sock_s1.send(b'give me the mac now')
        tagMAC = sock_s1.recv(2048)
        try:
            cipher_gcm.verify(tagMAC)
        except:
            print("-----the MAC is wrong, check it----")
        else:
            print("----the MAC is right, below is the message----")
            print(plaintext)
    else:
        print("I do not find the cert")

    sock_s1.close()