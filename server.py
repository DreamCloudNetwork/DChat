import os
import socket
import threading
import defines


def handle_client(client_socket, client_address, gpg_private_key_path, passphrase, gpg_public_key_path):
    print(f"Handling connection from: {client_address[0]}:{client_address[1]}")

    def start_get():
        try:
            with client_socket:
                while True:
                    data = client_socket.recv(1024).decode('utf-8')
                    if not data:
                        print(f"Connection closed by {client_address[0]}:{client_address[1]}")
                        break
                    # print()
                    # print(f"Received encrypted data: {data}")
                    decrypted_message = defines.decrypt_text_with_gpg_privatekey(data, gpg_private_key_path, passphrase)
                    print()
                    print(f"Received: {decrypted_message}")
                    print("Please input your message: ", end="")
        except Exception as e:
            print(f"Error occurred during receiving: {e}")
        finally:
            client_socket.close()

    def start_send():
        try:
            while True:
                reply = input("Please input your message: ")
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


def start_server():
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

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '0.0.0.0'
    port = 8846
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server is listening on {host}:{port}...")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Accepted connection from: {client_address[0]}:{client_address[1]}")
            client_thread = threading.Thread(target=handle_client, args=(
                client_socket, client_address, gpg_private_key_path, passphrase, gpg_public_key_path))
            client_thread.start()
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()
