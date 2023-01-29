import socket
#certificate assign
from OpenSSL import crypto, SSL
from os.path import join
import random
import hashlib, hmac, binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
# prepare for self-certification
CN = "CUHK"
k = crypto.PKey()
k.generate_key(crypto.TYPE_RSA,2048)
serialnumber=random.getrandbits(64)

# create a self-asigned cert named cert
cert = crypto.X509()
cert.get_subject().C = "CN" #country
cert.get_subject().ST = "HK" #state
cert.get_subject().L = "HK" #location,city
cert.get_subject().O = "CUHK" #oganization
cert.get_subject().OU = "CUHK" #organization unit
cert.get_subject().CN = CN #comman name
cert.set_serial_number(serialnumber)
# print(cert.get_subject())
# start and end time
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(31536000)

cert.set_issuer(cert.get_subject())
cert.set_pubkey(k)
cert.sign(k, 'sha512')
ca_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
ca_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)


# key1 = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
# key2 = crypto.dump_publickey(crypto.FILETYPE_PEM, k)
# key1_rsa = RSA.import_key(key1)
# key2_rsa = RSA.import_key(key2)
# print("private:{}\n".format(key1_rsa.exportKey()))
# print("public:{}\n".format(key2_rsa.exportKey()))

# first build a 1st connection between cuhk.py and blackboad.py
# it will be used for transmitting the authorised stu_cert
blackboard2cuhk = socket.socket()
blackboard2cuhk.bind(('127.0.0.1',3500))
blackboard2cuhk.listen(10)
print("waiting for blackboard....")
socket_blackboard2cuhk, addr_blackboard2cuhk = blackboard2cuhk.accept()
print("blackboard connected")
#
# socket_blackboard2cuhk = socket.socket()
# socket_blackboard2cuhk.connect(('127.0.0.2', 3500))

# build a 2nd connection between cuhk.py and student.py
# it is for listening to get the CSR request
stu2cuhk = socket.socket()
stu2cuhk.bind(('127.0.0.1', 3000))
stu2cuhk.listen(10)
print("waiting for the first student...")

while 1:
    # waiting for the student and listen to the csr from the student
    sock, addr = stu2cuhk.accept()
    # print(sock, addr)
    # recv_id = sock.recv(2048)
    # print("id:{}".format(recv_id))
    # sock.send('recv id'.encode('utf-8'))
    recv_csr = sock.recv(2048)
    print("\nreceive:{}".format(recv_csr.decode()))

    # sign and send the certs to the student
    certs = crypto.X509()
    csr_req = crypto.load_certificate_request(crypto.FILETYPE_PEM, recv_csr)
    certs.gmtime_adj_notBefore(0)
    certs.gmtime_adj_notAfter(31536000)
    certs.set_subject(csr_req.get_subject())
    certs.set_issuer(cert.get_subject())
    key = csr_req.get_pubkey()
    # pay attention here, we use the student public key
    certs.set_pubkey(key)
    # in signature we use cuhk key pair
    certs.sign(k, 'sha512')
    stu_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, certs)
    sock.send(stu_certificate)

    # stu_id = certs.get_subject().CN
    # print("-----stu_id:{}----\n".format(str(stu_id).encode('utf-8')))
    # socket_blackboard2cuhk.send(str(stu_id).encode('utf-8'))
    # socket_blackboard2cuhk.recv(2048)

    # send the certs to blackboard to verify
    socket_blackboard2cuhk.send(stu_certificate)
    sock.close()