import os
import socket
import threading
import gnupg
import defines

# 设置GPG密钥路径
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

# 初始化GnuPG对象
gpg = gnupg.GPG(gnupghome=gpg_home)

# 导入私钥
if gpg_private_key_path and os.path.exists(gpg_private_key_path):
    with open(gpg_private_key_path, 'rb') as key_file:
        import_result = gpg.import_keys(key_file.read())
        if not import_result.counts:
            raise ValueError("Failed to import private key.")

# 节点信息
node_port = int(input("请输入节点端口:"))
# input("按回车继续")
known_nodes = []  # 已知节点列表，格式为 [(host, port), ...]

# 处理客户端连接
def handle_client(client_socket, client_address):
    print(f"Handling connection from: {client_address[0]}:{client_address[1]}")

    def start_get():
        try:
            with client_socket:
                while True:
                    encrypted_data = client_socket.recv(1024).decode('utf-8')
                    if not encrypted_data:
                        print(f"Connection closed by {client_address[0]}:{client_address[1]}")
                        break
                    decrypted_message = defines.decrypt_text_with_gpg_privatekey(encrypted_data, gpg_private_key_path, passphrase)
                    print()
                    print(f"Received: {decrypted_message}")
                    print("请输入要发送的消息: ", end="")
        except Exception as e:
            print(f"Error occurred during receiving: {e}")
        finally:
            client_socket.close()

    def start_send():
        try:
            while True:
                reply = input("请输入要发送的消息: ")
                if reply.lower() == "exit":
                    break
                encrypted_message = defines.encrypt_text_with_gpg_pubkey(reply, gpg_public_key_path)
                defines.send_message_to_connected_socket(client_socket, encrypted_message)
        except Exception as e:
            print(f"Error occurred during sending: {e}")
        finally:
            client_socket.close()

    threads = []
    t1 = threading.Thread(target=start_get)
    threads.append(t1)
    t2 = threading.Thread(target=start_send)
    threads.append(t2)

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    print(f"Finished handling connection from: {client_address[0]}:{client_address[1]}")

# 监听连接
def start_listening():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '0.0.0.0'
    server_socket.bind((host, node_port))
    server_socket.listen(5)
    print(f"Node is listening on {host}:{node_port}...")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print("There is already a connection, stop inputting")
            print(f"Accepted connection from: {client_address[0]}:{client_address[1]}")
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
    finally:
        server_socket.close()

# 连接到其他节点
def connect_to_nodes():
    for host, port in known_nodes:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        defines.connect_to_server(host, port, client_socket)
        if client_socket:
            client_thread = threading.Thread(target=handle_client, args=(client_socket, (host, port)))
            client_thread.start()

# 主函数
if __name__ == "__main__":
    # 启动监听线程
    listening_thread = threading.Thread(target=start_listening)
    listening_thread.start()
    # 添加已知节点（示例）
    known_nodes.append((input("请输入对方的节点地址:"), int(input("请输入对方的节点端口:"))))  # 假设这是另一个节点的地址
    # 连接到已知节点
    connect_to_nodes()
