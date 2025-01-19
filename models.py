"""
Pycharm Include

Year:2024

Date:2024/3/5

Time:12:32

Write by KevinChang
"""
import gnupg

def encrypt_text_with_gpg_pubkey(text, pubkey_file_path):
    # 初始化GnuPG对象
    gpg = gnupg.GPG()

    # 加载公钥文件
    with open(pubkey_file_path, 'rb') as f:
        pub_key_data = f.read()
    imported_keys = gpg.import_keys(pub_key_data)

    if not imported_keys.count:
        raise Exception("Failed to import public key from file: " + pubkey_file_path)

    # 获取导入的公钥ID
    key_id = imported_keys.fingerprints[0]

    # 使用公钥加密文本
    encrypted_data = gpg.encrypt(text.encode('utf-8'), recipients=[key_id])

    if encrypted_data.ok:
        return encrypted_data.data.decode('utf-8')
    else:
        raise Exception("Encryption failed: " + encrypted_data.status)


import socket


def connect_to_server(host, port, client_socket_obj):
    client_socket = client_socket_obj

    try:
        # 尝试连接到服务器
        client_socket.connect((host, port))

        # 连接成功后可以发送和接收数据，这里仅打印连接成功信息
        print(f"Connected to server at {host}:{port}")

        # 在实际应用中，你可能需要在此处添加更多的逻辑，例如发送数据、接收响应等

    except (socket.error, ConnectionRefusedError) as e:
        print(f"Failed to connect to the server: {e}")
        return None

    finally:
        pass


def send_message_to_connected_socket(socket_obj, message):
    try:
        # 将字符串转换为字节并发送
        socket_obj.sendall(message.encode('utf-8'))

        # 在实际应用中，可能需要确认发送是否成功
        print("Message sent successfully.")

    except socket.error as e:
        print(f"Error occurred while sending data: {e}")
