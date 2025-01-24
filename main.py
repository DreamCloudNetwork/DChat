import os
import socket
import threading
import gnupg
import defines
import select
import sys

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
known_node = None  # 已知节点，格式为 (host, port)

# 标志变量，指示是否已经接受到连接
connection_received = False
connection_received_lock = threading.Lock()

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
    global connection_received
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '0.0.0.0'
    server_socket.bind((host, node_port))
    server_socket.listen(5)
    print(f"Node is listening on {host}:{node_port}...")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            with connection_received_lock:
                connection_received = True
            print("已接受到连接，停止输入对方节点信息")
            print(f"Accepted connection from: {client_address[0]}:{client_address[1]}")
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
            break  # 只处理一个连接
    finally:
        server_socket.close()

# 输入对方节点信息
def input_known_node():
    global connection_received, known_node
    print("请输入对方的节点地址 (或输入 'exit' 退出): ", end="")
    sys.stdout.flush()
    while not connection_received:
        input_ready, _, _ = select.select([sys.stdin], [], [], 0.1)  # 每0.1秒检查一次
        if input_ready:
            host = sys.stdin.readline().strip()
            if host.lower() == "exit":
                break
            sys.stdout.flush()
            port_str = input("请输入对方的节点端口: ")
            try:
                port = int(port_str)
                known_node = (host, port)
                break
            except ValueError:
                print("请输入有效的端口号")
                print("请输入对方的节点地址 (或输入 'exit' 退出): ", end="")
                sys.stdout.flush()
        with connection_received_lock:
            if connection_received:
                print("请输入要发送的消息: ", end="")
                break

# 连接到已知节点
def connect_to_node():
    if known_node:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        defines.connect_to_server(known_node[0], known_node[1], client_socket)
        if client_socket:
            client_thread = threading.Thread(target=handle_client, args=(client_socket, known_node))
            client_thread.start()

# 主函数
if __name__ == "__main__":
    # 启动监听线程
    listening_thread = threading.Thread(target=start_listening)
    listening_thread.start()

    # 启动输入线程
    input_thread = threading.Thread(target=input_known_node)
    input_thread.start()

    # 等待输入线程完成
    input_thread.join()

    # 连接到已知节点
    connect_to_node()
