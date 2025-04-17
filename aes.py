from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from hashlib import sha256
import os

def derive_key(password, salt, key_size=16):
    return PBKDF2(password, salt, dkLen=key_size, count=100_000)

def encrypt_file(input_path, output_path, password, iv_input, mode, key_size_bits):
    salt = os.urandom(16)
    key = derive_key(password.encode(), salt, key_size_bits // 8)

    with open(input_path, 'rb') as f:
        data = f.read()

    iv = sha256(iv_input.encode()).digest()[:16]

    if mode == 'EAX':
        cipher = AES.new(key, AES.MODE_EAX, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        with open(output_path, 'wb') as f:
            f.write(salt + tag + ciphertext)
    elif mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        with open(output_path, 'wb') as f:
            f.write(salt + ciphertext)

def decrypt_file(input_path, output_path, password, iv_input, mode, key_size_bits):
    with open(input_path, 'rb') as f:
        data = f.read()

    salt = data[:16]
    key = derive_key(password.encode(), salt, key_size_bits // 8)
    iv = sha256(iv_input.encode()).digest()[:16]

    try:
        if mode == 'EAX':
            tag = data[16:32]
            ciphertext = data[32:]
            cipher = AES.new(key, AES.MODE_EAX, nonce=iv)
            try:
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError:
                print("⚠️ Warning: Tag verification failed. Output may be incorrect.")
                plaintext = cipher.decrypt(ciphertext)  # Attempt anyway
        elif mode == 'CBC':
            ciphertext = data[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            try:
                plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            except ValueError:
                print("⚠️ Warning: Padding is incorrect. Output may be corrupted.")
                plaintext = cipher.decrypt(ciphertext)  # Save anyway

        with open(output_path, 'wb') as f:
            f.write(plaintext)
        print("✅ File decrypted and saved to:", output_path)

    except Exception as e:
        print("❌ Unexpected error during decryption:", str(e))

# === Main Program ===
print("🔐 AES File Encryptor/Decryptor")

choice = input("Do you want to (E)ncrypt or (D)ecrypt? ").strip().lower()
mode_input = input("Choose AES mode (EAX or CBC): ").strip().upper()
mode = 'CBC' if mode_input == 'CBC' else 'EAX'

while True:
    try:
        key_size = int(input("Choose key size (128 or 256): ").strip())
        if key_size not in [128, 256]:
            raise ValueError()
        break
    except ValueError:
        print("❗ Please enter 128 or 256.")

password = input("Enter a password: ").strip()
iv_input = input("Enter an IV (any string): ").strip()
input_path = input("Enter input file path: ").strip()
output_path = input("Enter output file path: ").strip()

if choice == 'e':
    encrypt_file(input_path, output_path, password, iv_input, mode, key_size)
    print("✅ File encrypted and saved to:", output_path)
elif choice == 'd':
    decrypt_file(input_path, output_path, password, iv_input, mode, key_size)
else:
    print("❗ Invalid choice. Please enter 'E' or 'D'.")


