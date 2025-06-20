
import socket
import pickle
import os
import struct
from crypto_utils import (
    load_key, encrypt_with_public_key, sign_with_private_key,
    encrypt_with_aes
)
from Crypto.Random import get_random_bytes
from colorama import init, Fore, Style

HOST = '127.0.0.1'
PORT = 12345

CLIENT_PRIVATE_KEY = os.path.join('keys', 'client_private.pem')
SERVER_PUBLIC_KEY = os.path.join('keys', 'server_public.pem')


def send_message(sock, packet_to_send):
    """封装消息并发送（报头+数据）"""
    # 计算数据包长度，并打包成8字节的报头
    msg_len = len(packet_to_send)
    header = struct.pack('!Q', msg_len)

    # 发送报头，然后发送实际数据
    sock.sendall(header + packet_to_send)


def main():
    s = socket.socket()
    s.connect((HOST, PORT))

    private_key = load_key(CLIENT_PRIVATE_KEY)
    server_pubkey = load_key(SERVER_PUBLIC_KEY)

    try:
        while True:
            print(Style.BRIGHT + Fore.LIGHTCYAN_EX + "-----------MENU-----------")
            print(Fore.CYAN + "1. send messages(RSA)")
            print(Fore.CYAN + "2. send csv file(hybrid encryption)")
            print(Fore.YELLOW + "q. quit")
            print(Fore.LIGHTCYAN_EX + "--------------------------" + Style.RESET_ALL)
            choice = input(Style.BRIGHT + Fore.BLUE + "Input your choice: ")

            packet_to_send = None  # 初始化

            if choice == '1':
                msg = input('Content: ')
                if not msg: continue
                data_bytes = msg.encode()
                encrypted = encrypt_with_public_key(data_bytes, server_pubkey)
                signature = sign_with_private_key(data_bytes, private_key)
                packet_to_send = pickle.dumps({
                    'type': 'text',
                    'encrypted': encrypted,
                    'signature': signature
                })

            elif choice == '2':
                filepath = input(Fore.WHITE + 'Input the file path: ')
                if not os.path.exists(filepath):
                    print(Fore.RED + "File doesn't exist.")
                    continue
                with open(filepath, 'rb') as f:
                    file_content = f.read()

                session_key = get_random_bytes(16)
                encrypted_content, nonce, tag = encrypt_with_aes(file_content, session_key)
                encrypted_session_key = encrypt_with_public_key(session_key, server_pubkey)
                signature = sign_with_private_key(file_content, private_key)
                packet_to_send = pickle.dumps({
                    'type': 'file',
                    'filename': os.path.basename(filepath),
                    'encrypted_session_key': encrypted_session_key,
                    'nonce': nonce,
                    'tag': tag,
                    'encrypted_content': encrypted_content,
                    'signature': signature
                })
                print(f"文件 '{os.path.basename(filepath)}' 已使用混合加密发送。")

            elif choice.lower() == 'q':
                print(Fore.YELLOW + "client closing...")
                break
            else:
                print(Fore.RED + "无效选项。")
                continue

            if packet_to_send:
                send_message(s, packet_to_send)

            response = s.recv(4096)
            print(Fore.GREEN + '服务器回应:', response.decode(errors='ignore'))

    except Exception as e:
        print(Fore.RED + f"出现异常: {e}")
    finally:
        s.close()


if __name__ == "__main__":
    main()