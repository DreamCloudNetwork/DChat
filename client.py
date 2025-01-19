import socket
import threading
import gnupg
import os
import defines

gpg_home = os.path.expanduser(os.environ.get('GNUPGHOME', '~/.gnupg'))
gpg_private_key_path = os.path.join(gpg_home, 'private_key.asc')
gpg_public_key_path = os.path.join(gpg_home, 'public_key.asc')

# 检查密钥文件是否存在
if not os.path.exists(gpg_private_key_path) or not os.path.exists(gpg_public_key_path):
    print("密钥对未找到。正在生成新的密钥对...")
    name_email = input("请输入你的邮箱: ")
    passphrase = input("请输入私钥密码: ")
    gpg_public_key_path, gpg_private_key_path = defines.generate_gpg_keypair(gpg_home,
                                                                             name_email=name_email,
                                                                             passphrase=passphrase)
else:
    passphrase = input("请输入私钥密码: ")

Server_Port = 8846
Server_Host = input("服务器地址: ")

# 初始化GnuPG对象
gpg = gnupg.GPG(gnupghome=gpg_home)

# 导入私钥
if gpg_private_key_path and os.path.exists(gpg_private_key_path):
    with open(gpg_private_key_path, 'rb') as key_file:
        import_result = gpg.import_keys(key_file.read())
        if not import_result.counts:
            raise ValueError("Failed to import private key.")

# 创建客户端套接字
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
defines.connect_to_server(Server_Host, Server_Port, client_socket)


def start_send():
    while True:
        message = input("请输入要发送的消息: ")
        print()
        encrypted_message = defines.encrypt_text_with_gpg_pubkey(message, gpg_public_key_path)
        defines.send_message_to_connected_socket(client_socket, encrypted_message)


def start_get():
    while True:
        encrypted_data = client_socket.recv(1024).decode('utf-8')
        if not encrypted_data:
            print("Connection closed by the server.")
            break
        print()
        decrypted_message = defines.decrypt_text_with_gpg_privatekey(encrypted_data, gpg_private_key_path,
                                                                     passphrase=passphrase)
        print("收到消息:", decrypted_message)
        print("请输入要发送的消息:", end="")


threads = []
t1 = threading.Thread(target=start_send)
threads.append(t1)
t2 = threading.Thread(target=start_get)
threads.append(t2)

if __name__ == "__main__":
    for t in threads:
        t.start()
