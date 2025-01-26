import os
import socket
import threading
import gnupg
import defines
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from loguru import logger
from ttkbootstrap import Style


class ChatApp:
    def __init__(self, tk_root):
        self.public_key_label = None
        self.init_submit_button = None
        self.send_button = None
        logger.add(os.path.expanduser("./DChat.log"))
        self.passphrase = None
        self.message_entry = None
        self.chat_text = None
        self.status_label = None
        self.submit_button = None
        self.host_entry = None
        self.port_entry = None
        self.local_port_entry = None
        self.passphrase_entry = None
        self.root = tk_root
        self.client_socket = None
        self.gpg_home = os.path.expanduser(os.environ.get('GNUPGHOME', '~/.gnupg'))
        self.gpg_private_key_path = os.path.join(self.gpg_home, 'private_key.asc')
        self.gpg_public_key_path = os.path.join(self.gpg_home, 'public_key.asc')  # 默认公钥路径
        self.selected_public_key_path = None  # 用户选择的公钥路径
        self.gpg = gnupg.GPG(gnupghome=self.gpg_home)
        self.connected = False  # 连接状态变量
        self.local_port = None  # 初始化 local_port
        self.address_family = socket.AF_INET  # 默认使用IPv4
        self.check_ipv6_support()
        self.create_widgets()
        self.load_keys()

    def check_ipv6_support(self):
        if socket.has_ipv6:
            choice = messagebox.askyesno("选择协议", "您的系统支持IPv6，是否使用IPv6？")
            if choice:
                self.address_family = socket.AF_INET6
            else:
                self.address_family = socket.AF_INET
        else:
            self.address_family = socket.AF_INET

    def create_widgets(self):
        # 创建左右布局
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(main_frame, width=240)
        right_frame = ttk.Frame(main_frame, width=560)

        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # 左边布局：初始化本地节点
        ttk.Label(left_frame, text="初始化本地节点").pack(pady=10)

        # 左边布局：私钥密码输入
        ttk.Label(left_frame, text="私钥密码:").pack()
        self.passphrase_entry = ttk.Entry(left_frame, show="*")
        self.passphrase_entry.pack(pady=5)

        # 本地节点端口输入
        ttk.Label(left_frame, text="本地节点端口:").pack()
        self.local_port_entry = ttk.Entry(left_frame)
        self.local_port_entry.pack(pady=5)

        # 选择 GPG 公钥文件
        ttk.Label(left_frame, text="选择 GPG 公钥文件:").pack(pady=5)
        self.public_key_label = ttk.Label(left_frame, text="未选择")
        self.public_key_label.pack(pady=5)
        ttk.Button(left_frame, text="选择公钥文件", command=self.select_public_key_file).pack(pady=5)

        # 初始化确定按钮
        self.init_submit_button = ttk.Button(left_frame, text="确定", command=self.init_local_node)
        self.init_submit_button.pack(pady=10)

        # 左边布局：连接节点
        ttk.Label(left_frame, text="连接节点").pack(pady=10)

        # 节点地址输入
        ttk.Label(left_frame, text="节点地址:").pack()
        self.host_entry = ttk.Entry(left_frame)
        self.host_entry.pack(pady=5)

        # 节点端口输入
        ttk.Label(left_frame, text="节点端口:").pack()
        self.port_entry = ttk.Entry(left_frame)
        self.port_entry.pack(pady=5)

        # 确定按钮
        self.submit_button = ttk.Button(left_frame, text="连接", command=self.submit_entries, state=tk.DISABLED)
        self.submit_button.pack(pady=10)

        # 状态标签
        self.status_label = ttk.Label(left_frame, text="")
        self.status_label.pack(pady=5)

        # 右边布局：聊天记录
        self.chat_text = tk.Text(right_frame, wrap=tk.WORD)
        self.chat_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        chat_scrollbar = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.chat_text.yview)
        chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_text.config(yscrollcommand=chat_scrollbar.set)

        self.message_entry = ttk.Entry(right_frame)
        self.message_entry.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)
        self.send_button = ttk.Button(right_frame, text="发送", command=self.send_message, state=tk.DISABLED)
        self.send_button.pack(side=tk.BOTTOM, fill=tk.X, padx=10)

    def select_public_key_file(self):
        file_path = filedialog.askopenfilename(
            title="选择 GPG 公钥文件",
            filetypes=[("ASCII Armor Files", "*.asc"), ("All Files", "*.*")]
        )
        if file_path:
            self.selected_public_key_path = file_path
            self.public_key_label.config(text=f"已选择: {os.path.basename(file_path)}")

    def send_message_to_connected_socket(self, message):
        try:
            self.client_socket.send(message.encode('utf-8'))
            logger.info("Message sent successfully.")
        except socket.error as e:
            logger.error(f"Error occurred while sending data: {e}")

    def init_local_node(self):
        self.passphrase = self.passphrase_entry.get().strip()
        local_port = self.local_port_entry.get().strip()

        if not self.passphrase or not local_port:
            self.status_label.config(text="请填写私钥密码和本地节点端口")
            return
        if not self.selected_public_key_path:
            self.status_label.config(text="请选择公钥文件")
            return

        try:
            local_port = int(local_port)
        except ValueError:
            self.status_label.config(text="请输入有效的本地节点端口号")
            return

        # 更新 local_port
        self.local_port = local_port

        # 启动监听线程
        self.start_listening_thread()

        # 启用连接按钮
        self.submit_button.config(state=tk.NORMAL)

        self.status_label.config(text="初始化本地节点成功")

    def submit_entries(self):
        host = self.host_entry.get().strip()
        port = self.port_entry.get().strip()

        # 连接到已知节点（如果提供了节点地址和端口）
        if host and port:
            try:
                port = int(port)
                known_node = (host, port)
                client_socket = socket.socket(self.address_family, socket.SOCK_STREAM)
                if client_socket and not defines.connect_to_server(known_node[0], known_node[1], client_socket):
                    self.client_socket = client_socket
                    client_thread = threading.Thread(target=self.handle_client, args=(client_socket, known_node))
                    client_thread.start()
                    self.connected = True
                    self.submit_button.config(state=tk.DISABLED)  # 连接成功后禁用提交按钮
                    self.send_button.config(state=tk.NORMAL)
                    self.status_label.config(text="连接成功")
            except ValueError:
                self.status_label.config(text="请输入有效的节点端口号")
            except Exception as e:
                self.status_label.config(text=f"连接失败: {e}")
        else:
            self.status_label.config(text="本地节点已启动，等待连接")

    def get_user_input(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("生成密钥对")
        dialog.geometry("300x200")

        ttk.Label(dialog, text="邮箱地址:").pack(pady=5)
        email_entry = ttk.Entry(dialog)
        email_entry.pack(pady=5)

        ttk.Label(dialog, text="私钥密码:").pack(pady=5)
        passphrase_entry = ttk.Entry(dialog, show="*")
        passphrase_entry.pack(pady=5)

        def on_submit():
            email = email_entry.get().strip()
            passphrase = passphrase_entry.get().strip()
            if email and passphrase:
                dialog.result = (email, passphrase)
                dialog.destroy()
            else:
                messagebox.showwarning("警告", "请填写所有必要的信息。")

        submit_button = ttk.Button(dialog, text="提交", command=on_submit)
        submit_button.pack(pady=10)

        dialog.result = None
        dialog.wait_window()
        return dialog.result

    def load_keys(self):
        if not os.path.exists(self.gpg_private_key_path) or not os.path.exists(self.gpg_public_key_path):
            logger.warning("密钥对未找到。正在生成新的密钥对...")
            result = self.get_user_input()
            if result:
                name_email, passphrase = result
                logger.debug(f"正在使用名称和邮箱地址生成密钥对: {name_email}")
                keypair_paths = defines.generate_gpg_keypair(
                    self.gpg_home,
                    name_email=name_email,
                    passphrase=passphrase
                )
                self.gpg_public_key_path, self.gpg_private_key_path = keypair_paths
            else:
                messagebox.showerror("错误", "未提供必要的信息，无法生成密钥对。")
                logger.error("未提供必要的信息，无法生成密钥对。")
                return
        else:
            logger.info("密钥对已存在。")

        if os.path.exists(self.gpg_private_key_path):
            with open(self.gpg_private_key_path, 'rb') as key_file:
                import_result = self.gpg.import_keys(key_file.read())
                if not import_result.counts:
                    logger.error("Failed to import private key.")
                    raise ValueError("Failed to import private key.")

    def handle_client(self, client_socket, client_address):
        logger.info(f"Handling connection from: {client_address[0]}:{client_address[1]}")

        def start_get():
            try:
                with client_socket:
                    while True:
                        encrypted_data = client_socket.recv(1024).decode('utf-8')
                        if not encrypted_data:
                            logger.warning(f"Connection closed by {client_address[0]}:{client_address[1]}")
                            break
                        decrypted_message = defines.decrypt_text_with_gpg_privatekey(encrypted_data,
                                                                                     self.gpg_private_key_path,
                                                                                     self.passphrase)
                        self.chat_text.insert(tk.END, f"Received: {decrypted_message}\n")
                        logger.trace(f"Received: {decrypted_message}")
                        self.chat_text.see(tk.END)
            except Exception as e:
                logger.error(f"Error occurred during receiving: {e}")
            finally:
                client_socket.close()

        threads = []
        t1 = threading.Thread(target=start_get)
        threads.append(t1)

        for t in threads:
            t.start()

        logger.success(f"Finished handling connection from: {client_address[0]}:{client_address[1]}")
        self.send_button.config(state=tk.NORMAL)

    def start_listening_thread(self):
        if self.local_port is not None:
            listening_thread = threading.Thread(target=self.start_listening, args=(self.local_port,))
            listening_thread.daemon = True
            listening_thread.start()

    def start_listening(self, local_port):
        server_socket = socket.socket(self.address_family, socket.SOCK_STREAM)
        host = '::' if self.address_family == socket.AF_INET6 else '0.0.0.0'
        try:
            server_socket.bind((host, local_port))
            server_socket.listen(5)
            logger.info(f"Node is listening on {host}:{local_port}...")

            try:
                while True:
                    client_socket, client_address = server_socket.accept()
                    logger.trace("已接受到连接，停止输入对方节点信息")
                    logger.trace(f"Accepted connection from: {client_address[0]}:{client_address[1]}")
                    self.client_socket = client_socket
                    client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
                    client_thread.start()
                    break  # 只处理一个连接
            finally:
                server_socket.close()
        except Exception as e:
            self.status_label.config(text=f"监听失败: {e}")

    def send_message(self):
        reply = self.message_entry.get().strip()
        if reply.lower() == "exit":
            self.root.quit()
        elif reply and self.client_socket:  # 检查是否有非空内容和有效的 client_socket
            public_key_path = self.selected_public_key_path or self.gpg_public_key_path
            encrypted_message = defines.encrypt_text_with_gpg_pubkey(reply, public_key_path)
            self.send_message_to_connected_socket(encrypted_message)
            self.chat_text.insert(tk.END, f"Sent: {reply}\n")
            logger.trace(f"Sent: {reply}")
            self.chat_text.see(tk.END)
            self.message_entry.delete(0, tk.END)


if __name__ == "__main__":
    root = Style(theme="minty").master
    root.title("DChat P2P")
    root.geometry("800x600")
    app = ChatApp(root)
    root.mainloop()
