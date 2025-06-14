import socket
import pickle
import os
from crypto_utils import load_key, decrypt_with_private_key, verify_signature

HOST = '127.0.0.1'
PORT = 12345

# 密钥文件路径
SERVER_PRIVATE_KEY = os.path.join('keys', 'server_private.pem')
CLIENT_PUBLIC_KEY = os.path.join('keys', 'client_public.pem')

def process_encrypted_packet(packet: bytes):
    server_privkey = load_key(SERVER_PRIVATE_KEY)
    client_pubkey = load_key(CLIENT_PUBLIC_KEY)
    try:
        obj = pickle.loads(packet)
        encrypted = obj['encrypted']
        signature = obj['signature']
        data = decrypt_with_private_key(encrypted, server_privkey)
        if verify_signature(data, signature, client_pubkey):
            return data.decode(), True
        else:
            return '[签名验证失败]', False
    except Exception as e:
        return f'[解密/验签异常: {e}]', False

s = socket.socket()
s.bind((HOST, PORT))
s.listen(1)

print(f"服务器启动，等待客户端连接...")

conn, addr = s.accept()
print(f"连接来自: {addr}")

try:
    while True:
        data = conn.recv(4096)
        if not data:
            print("客户端已断开")
            break
        msg, ok = process_encrypted_packet(data)
        print('客户端:', msg)
        send_msg = input('你要发送给客户端的内容: ')
        conn.sendall(send_msg.encode())
except Exception as e:
    print("出现异常:", e)
finally:
    conn.close()
    s.close()