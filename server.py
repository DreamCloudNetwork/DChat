"""
Pycharm Include

Year:2024

Date:2024/3/5

Time:12:52

Write by KevinChang
"""
import socket
import gnupg
def decrypt_text_with_gpg_privatekey(encrypted_text, secring_file_path, passphrase=None):
    # 初始化GnuPG对象
    gpg = gnupg.GPG()

    # 设置私钥环路径
    gpg.options = ['--homedir', '/path/to/gnupg/home']  # 替换为实际的gnupg主目录路径
    if secring_file_path:
        gpg.options.extend(['--secret-keyring', secring_file_path])

    try:
        # 解密数据
        decrypted_data = gpg.decrypt(encrypted_text.encode('utf-8'), passphrase=passphrase)

        if decrypted_data.ok:
            return decrypted_data.data
        else:
            raise Exception("Decryption failed: " + decrypted_data.status)

    except Exception as e:
        print(f"Error occurred during decryption: {e}")
        return None
def start_server():
    GPG_PritiveKey = input("请输入私钥文件路径:")
    GPG_key = input("Key:")
    # 创建一个Socket对象
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 设置端口号和主机名（'0.0.0.0'表示监听所有网络接口）
    host = '0.0.0.0'
    port = 8846

    # 绑定到指定的IP地址和端口
    server_socket.bind((host, port))

    # 设置最大连接数（队列长度）
    server_socket.listen(5)

    print(f"Server is listening on {host}:{port}...")
    client_socket, client_address = server_socket.accept()

    print(f"Accepted connection from: {client_address[0]}:{client_address[1]}")
    while True:
        # 接受新的客户端连接请求


        try:
            # 接收客户端发送的数据并打印
            data = client_socket.recv(1024).decode('utf-8')
            if data != "exit":

                #print("Received:", data)
                print("Received:",decrypt_text_with_gpg_privatekey(data,GPG_PritiveKey))
                # 发送回复消息给客户端
                reply = input("Please input your message: ")
                client_socket.sendall(reply.encode('utf-8'))
            else:
                client_socket.close()
        except Exception as e:
            print(f"Error occurred: {e}")

        finally:
            # 关闭与客户端的连接
            pass

# 启动服务器
start_server()
