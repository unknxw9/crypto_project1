import socket
import pickle
import os
from crypto_utils import load_key, encrypt_with_public_key, sign_with_private_key

HOST = '127.0.0.1'
PORT = 12345

# 密钥文件路径
CLIENT_PRIVATE_KEY = os.path.join('keys', 'client_private.pem')
SERVER_PUBLIC_KEY = os.path.join('keys', 'server_public.pem')

def prepare_encrypted_message(plain: str) -> bytes:
    private_key = load_key(CLIENT_PRIVATE_KEY)
    server_pubkey = load_key(SERVER_PUBLIC_KEY)
    data_bytes = plain.encode()
    encrypted = encrypt_with_public_key(data_bytes, server_pubkey)
    signature = sign_with_private_key(data_bytes, private_key)
    # 用pickle打包密文和签名
    packet = pickle.dumps({'encrypted': encrypted, 'signature': signature})
    return packet

s = socket.socket()
s.connect((HOST, PORT))

try:
    while True:
        send_msg = input('你要发送给服务器的内容: ')
        if not send_msg:
            continue
        to_send = prepare_encrypted_message(send_msg)
        s.sendall(to_send)
        data = s.recv(4096)
        if not data:
            print('服务器已断开')
            break
        print('服务器:', data.decode(errors='ignore'))
except Exception as e:
    print("出现异常:", e)
finally:
    s.close()