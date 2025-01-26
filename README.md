# DChat

## 简介

DChat 是一个基于Python的点对点（P2P）聊天应用程序，使用GPG进行加密通信，确保消息的安全性。该应用程序支持IPv4和IPv6协议，并提供图形用户界面（GUI）进行交互。

## 特性

- **点对点通信**：直接在用户之间进行通信，无需中央服务器。
- **GPG加密**：使用GPG进行消息加密和解密，确保消息的安全性。
- **IPv4和IPv6支持**：根据系统支持情况选择使用IPv4或IPv6协议。
- **图形用户界面**：提供直观的GUI，方便用户进行操作。

## 安装

### 前提条件

- Python 3.6 或更高版本
- `tkinter` 库（通常随Python安装）

### 安装步骤

1. **克隆仓库**
    ```bash 
    git clone https://github.com/yourusername/DChat.git 
    cd DChat
   ```
2. **创建虚拟环境（可选但推荐）**
    ```bash
    python -m venv venv 
   source venv/bin/activate # 在Windows上使用 venv\Scripts\activate
   ```
3. **安装依赖**
    ```bash 
   pip install -r requirements.txt
   ```   
## 使用方法

### 启动应用程序
```bash
python main.py
```
### 功能说明

1. **初始化本地节点**
   - 如果电脑支持IPv6，程序会弹窗提示选择使用IPv6或IPv4。
   - 如果密钥对不存在，程序会弹出对话框要求用户输入邮箱地址和私钥密码，然后生成新的密钥对。
   - 输入私钥密码。
   - 输入本地节点端口。
   - 选择公钥文件。
   - 点击“确定”按钮启动本地节点。

2. **连接节点**
   - 输入节点地址。
   - 输入节点端口。
   - 点击“连接”按钮连接到已知节点。

3. **聊天**
   - 在聊天记录区域查看消息。
   - 在输入框中输入消息并点击“发送”按钮发送消息。

### 密钥对管理

- 如果检测到不存在GPG密钥对，程序会弹出对话框要求用户输入邮箱地址和私钥密码，然后生成新的密钥对。
- 密钥对存储在GPG主目录中，默认路径为`~/.gnupg`。

## 依赖项

- `python-gnupg`：用于生成和管理GPG密钥对，以及加密和解密消息。
- `tkinter`：用于创建图形用户界面。
- `loguru`：用于日志记录。

## 日志

日志文件存储在当前目录下的`DChat.log`文件中。日志级别包括`INFO`、`DEBUG`、`ERROR`等。

## 贡献

欢迎贡献代码、报告问题或提出建议。

## 许可证

本项目采用[GNU GENERAL PUBLIC许可证](LICENSE)。

## 联系

- **作者**: Kevin Chang
- **邮箱**: 35583291@qq.com
- **GitHub**: [kevin126ckw](https://github.com/kevin126ckw)




   

   