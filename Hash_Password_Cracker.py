from hashlib import md5, sha1, sha256
import sys
import threading
import queue
from time import time

uncracked = True
correct_password = ''
threadsl = []
start_time = time()

def hash_crack(hash_function):
    global uncracked, correct_password
    while uncracked and not q.empty():
        pwd = q.get()
        print("Trying .. {}".format(pwd))
        hashed_pwd = hash_function(pwd.encode('utf-8')).hexdigest()
        if hashed_pwd == sample_hash:
            print("[+] Hash matched for: {}".format(pwd))
            uncracked = False
            correct_password = pwd
        q.task_done()

q = queue.Queue()
sample_hash = sys.argv[1]
hash_type = sys.argv[2]
threads = int(sys.argv[3])

with open('wordlists/password_list.txt', 'r') as file:
    for password in file.read().splitlines():
        q.put(password)

hash_functions = {
    'md5': md5,
    'sha1': sha1,
    'sha256': sha256
}

if hash_type in hash_functions:
    for i in range(threads):
        t = threading.Thread(target=hash_crack, args=(hash_functions[hash_type],), daemon=True)
        t.start()
        threadsl.append(t)
else:
    print("Invalid hash type provided.")

for t in threadsl:
    t.join()

if not uncracked:
    print("[+] Given hash cracked with password: {}".format(correct_password))
else:
    print("[+] No hashes cracked")

print("Time taken: {}".format(time() - start_time))
