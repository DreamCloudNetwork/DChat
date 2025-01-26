import gnupg
import os
import socket
from loguru import logger

def decrypt_text_with_gpg_privatekey(encrypted_text, secring_file_path, passphrase=None):
    gpg_home = os.path.expanduser(os.environ.get('GNUPGHOME', '~/.gnupg'))
    if not os.path.exists(gpg_home):
        logger.error("GPG home directory doesNotExist.")
        raise FileNotFoundError(f"GPG home directory {gpg_home} doesNotExist.")

    gpg = gnupg.GPG(gnupghome=gpg_home)

    if secring_file_path and os.path.exists(secring_file_path):
        with open(secring_file_path, 'rb') as key_file:
            import_result = gpg.import_keys(key_file.read())
            if not import_result.counts:
                logger.error("Failed to import private key.")
                raise ValueError("Failed to import private key.")

    try:
        decrypted_data = gpg.decrypt(encrypted_text, passphrase=passphrase)
        if decrypted_data.ok:
            return decrypted_data.data.decode('utf-8')
        else:
            logger.error(f"Decryption failed: {decrypted_data.status}")
            raise Exception(f"Decryption failed: {decrypted_data.status}")
    except Exception as e:
        logger.error(f"Error occurred during decryption: {e}")
        print(f"Error occurred during decryption: {e}")
        return None


def encrypt_text_with_gpg_pubkey(text, pubkey_file_path):
    gpg = gnupg.GPG()

    if os.path.exists(pubkey_file_path):
        with open(pubkey_file_path, 'rb') as f:
            pub_key_data = f.read()
        imported_keys = gpg.import_keys(pub_key_data)
        if not imported_keys.counts:
            logger.error(f"Failed to import public key from file: {pubkey_file_path}")
            raise Exception(f"Failed to import public key from file: {pubkey_file_path}")

        key_id = imported_keys.fingerprints[0]
        encrypted_data = gpg.encrypt(text, key_id, always_trust=True)
        if not encrypted_data.ok:
            logger.error(f"Encryption failed: {encrypted_data.status}, {encrypted_data.stderr}")
            raise Exception(f"Encryption failed: {encrypted_data.status}, {encrypted_data.stderr}")
        return str(encrypted_data)
    else:
        logger.error(f"Public key file not found: {pubkey_file_path}")
        raise FileNotFoundError(f"Public key file not found: {pubkey_file_path}")



def generate_gpg_keypair(gpg_home, name_email, passphrase):
    gpg = gnupg.GPG(gnupghome=gpg_home)

    # 生成密钥对
    input_data = gpg.gen_key_input(
        name_email=name_email,
        passphrase=passphrase
    )
    key = gpg.gen_key(input_data)

    # 导出公钥
    public_key = gpg.export_keys(key.fingerprint)
    public_key_path = os.path.join(gpg_home, 'public_key.asc')
    with open(public_key_path, 'wb') as public_key_file:
        public_key_file.write(public_key.encode('utf-8'))

    # 导出私钥
    private_key = gpg.export_keys(key.fingerprint, secret=True, passphrase=passphrase)
    private_key_path = os.path.join(gpg_home, 'private_key.asc')
    with open(private_key_path, 'wb') as private_key_file:
        private_key_file.write(private_key.encode('utf-8'))

    return public_key_path, private_key_path



def connect_to_server(host, port, client_socket_obj):
    try:
        client_socket_obj.connect((host, port))
        logger.info(f"Connected to server at {host}:{port}")
        # 发送初始消息（可选）
        # welcome_message = "Hello Server!"
        # send_message_to_connected_socket(client_socket_obj, welcome_message)
    except (socket.error, ConnectionRefusedError) as e:
        logger.error(f"Failed to connect to the server: {e}")
        return e




