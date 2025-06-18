
import socket
import pickle
import os
import struct  # <-- 1. 导入 struct 模块
from crypto_utils import (
    load_key, decrypt_with_private_key, verify_signature,
    decrypt_with_aes
)

HOST = '127.0.0.1'
PORT = 12345
SERVER_PRIVATE_KEY = os.path.join('keys', 'server_private.pem')
CLIENT_PUBLIC_KEY = os.path.join('keys', 'client_public.pem')
RECEIVED_FILES_DIR = 'received_files'


# 确保接收所有数据
def recv_all(sock, n):
    """确保从套接字接收n个字节的数据"""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data


def recv_message(sock):
    """接收一个完整的消息（报头+数据）"""
    # 3. 先接收8字节的报头
    raw_msg_len = recv_all(sock, 8)
    if not raw_msg_len:
        return None

    # 4. 从报头中解包出数据长度
    msg_len = struct.unpack('!Q', raw_msg_len)[0]

    # 5. 根据长度接收完整的数据
    return recv_all(sock, msg_len)


def process_packet(packet: bytes):
    if not os.path.exists(RECEIVED_FILES_DIR):
        os.makedirs(RECEIVED_FILES_DIR)

    server_privkey = load_key(SERVER_PRIVATE_KEY)
    client_pubkey = load_key(CLIENT_PUBLIC_KEY)

    try:
        data_dict = pickle.loads(packet)
        packet_type = data_dict.get('type')

        if packet_type == 'text':
            encrypted = data_dict['encrypted']
            signature = data_dict['signature']
            data = decrypt_with_private_key(encrypted, server_privkey)
            if verify_signature(data, signature, client_pubkey):
                return f"收到文本: {data.decode()}", True
            else:
                return '[文本签名验证失败]', False

        elif packet_type == 'file':
            encrypted_session_key = data_dict['encrypted_session_key']
            session_key = decrypt_with_private_key(encrypted_session_key, server_privkey)

            nonce = data_dict['nonce']
            tag = data_dict['tag']
            encrypted_content = data_dict['encrypted_content']
            decrypted_content = decrypt_with_aes(encrypted_content, nonce, tag, session_key)

            if decrypted_content is None:
                return "[文件解密或完整性验证失败]", False

            signature = data_dict['signature']
            if verify_signature(decrypted_content, signature, client_pubkey):
                filename = os.path.basename(data_dict.get("filename", "unknown_file"))
                save_path = os.path.join(RECEIVED_FILES_DIR, filename)
                with open(save_path, 'wb') as f:
                    f.write(decrypted_content)
                return f"收到文件 '{filename}' 并成功解密保存。", True
            else:
                return '[文件签名验证失败]', False
        else:
            return '[未知数据包类型]', False
    except Exception as e:
        return f'[处理数据包时出现异常: {e}]', False


def main():
    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen(1)

    print(f"服务器启动，在 {HOST}:{PORT} 等待连接...")
    conn, addr = s.accept()
    print(f"连接来自: {addr}")

    try:
        while True:
            # 获取完整消息
            data = recv_message(conn)
            if not data:
                print("客户端已断开")
                break

            msg, ok = process_packet(data)
            print('处理结果:', msg)

            if ok:
                conn.sendall(b'Data received and processed successfully.')
            else:
                conn.sendall(b'Error processing data.')

    except Exception as e:
        print(f"出现异常: {e}")
    finally:
        conn.close()
        s.close()
        print("服务器已关闭。")


if __name__ == "__main__":
    main()