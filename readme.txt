This code is tested in anaconda with the following environment:
python 3.9.0
pyOpenSSL 22.1.0
pycryptodome 3.15.0

The activation steps:
step 1.python CUHK.py
step 2.python Blackboard.py
step 3.python Student.py student_id

step 3 can do multiple times

The CUHK and Blackboard will continuously waiting for the Student.py connnection.

After CUHK sign the cert for student, CUHK will tranfer a copy of the cert to Blackboard for verificatoin
using socket, so there is a continuous connection between CUHK and Blackboard. The connection of
CUHK-student and Blackboard-student will be closed each time.

In Step 6 I use AES GCM mode to generate the MAC. The session key is excrypted and transported 
but the iv is a simple bytearray define at beginning in python program, not transported. And the 
encryption and MAC will be transferred seperately.