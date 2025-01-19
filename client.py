"""
Pycharm Include

Year:2024

Date:2024/3/5

Time:12:22

Write by KevinChang
"""
import gnupg
import models
import socket
import threading



GPG_Pritave_File = input("GPG私钥文件路径:")
GPG_Public_FIle = input("GPG公钥文件路径:")
Server_Port = 8846
Server_Host = input("服务器地址:")

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
models.connect_to_server(Server_Host, Server_Port, client_socket)
def start_send():
    while True:
        message = input("请输入要发送的消息:")
        print()
        send_message = models.encrypt_text_with_gpg_pubkey(message, GPG_Public_FIle)
        models.send_message_to_connected_socket(client_socket, send_message)

def start_get():
    while True:
        # 无限制地接收数据（直到有数据可读或者连接断开）
        data = client_socket.recv(1024).decode('utf-8')

        if not data:
            print("Connection closed by the server.")
            break
        print()
        print("收到消息",data)
        print("请输入要发送的消息:",end="")
threads = []  # 定义一个线程池
t1 = threading.Thread(target=start_send)
threads.append(t1)  # 把t1线程装到线程池里
t2 = threading.Thread(target=start_get)
threads.append(t2)  # 把t2线程装到线程池里
if __name__ == "__main__":
    for t in threads:
        t.start()
