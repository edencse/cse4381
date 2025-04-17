from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import sys
import mimetypes

KEY_FOLDER = "keys"

os.makedirs(KEY_FOLDER, exist_ok=True)

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(os.path.join(KEY_FOLDER, "private.pem"), "wb") as f:
        f.write(private_key)

    with open(os.path.join(KEY_FOLDER, "public.pem"), "wb") as f:
        f.write(public_key)

    print("Keys generated: private.pem and public.pem")

def encrypt_file(input_file, public_key_file):
    with open(input_file, 'rb') as f:
        data = f.read()

    # Generate AES session key
    session_key = get_random_bytes(16)

    # Encrypt the data with AES
    cipher_aes = AES.new(session_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(data, AES.block_size))

    # Encrypt the AES key with RSA
    with open(public_key_file, 'rb') as f:
        recipient_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    ext = os.path.splitext(input_file)[1]
    output_file = f"encrypted{ext}"

    with open(output_file, 'wb') as f:
        f.write(encrypted_session_key)
        f.write(cipher_aes.iv)
        f.write(ciphertext)

    print(f"Encrypted file saved as {output_file}")

def decrypt_file(encrypted_file, private_key_file):
    with open(encrypted_file, 'rb') as f:
        encrypted_session_key = f.read(256)  # RSA 2048 = 256 bytes
        iv = f.read(16)
        ciphertext = f.read()

    with open(private_key_file, 'rb') as f:
        private_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    data = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)

    ext = os.path.splitext(encrypted_file)[1]
    output_file = f"decrypted{ext}"

    with open(output_file, 'wb') as f:
        f.write(data)

    print(f"Decrypted file saved as {output_file}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Encrypt/Decrypt files using RSA + AES hybrid encryption")
    parser.add_argument("mode", choices=["generate", "encrypt", "decrypt"], help="Operation mode")
    parser.add_argument("--file", help="Input file")
    parser.add_argument("--key", help="Path to .pem key file")

    args = parser.parse_args()

    if args.mode == "generate":
        generate_keys()
    elif args.mode == "encrypt":
        if not args.file or not args.key:
            print("Encryption requires --file and --key (public key).")
        else:
            encrypt_file(args.file, args.key)
    elif args.mode == "decrypt":
        if not args.file or not args.key:
            print("Decryption requires --file and --key (private key).")
        else:
            decrypt_file(args.file, args.key)
