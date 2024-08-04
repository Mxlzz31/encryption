from flask import Flask, request, render_template
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)

# Caesar Cipher Functions
def caesar_cipher_encrypt(plaintext, shift):
    encrypted_text = ""
    for char in plaintext:
        if char.isalpha():
            shift_amount = shift % 26
            start = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr(start + (ord(char) - start + shift_amount) % 26)
            encrypted_text += encrypted_char
        else:
            encrypted_text += char
    return encrypted_text

def caesar_cipher_decrypt(ciphertext, shift):
    return caesar_cipher_encrypt(ciphertext, -shift)

# AES Encryption/Decryption Functions
def aes_encrypt(plaintext, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB(key[:16]), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(encrypted_data).decode('utf-8')

def aes_decrypt(ciphertext, key):
    encrypted_data = base64.b64decode(ciphertext)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB(key[:16]), backend=backend)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode('utf-8')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/caesar', methods=['GET', 'POST'])
def caesar():
    result = {}
    if request.method == 'POST':
        text = request.form['caesar_text']
        shift = int(request.form['caesar_shift'])
        encrypted = caesar_cipher_encrypt(text, shift)
        decrypted = caesar_cipher_decrypt(encrypted, shift)
        result = {
            'original': text,
            'encrypted': encrypted,
            'decrypted': decrypted
        }
    return render_template('caesar.html', result=result)

@app.route('/aes', methods=['GET', 'POST'])
def aes():
    result = {}
    if request.method == 'POST':
        text = request.form['aes_text']
        key = request.form['aes_key'].encode()
        if len(key) not in [16, 24, 32]:
            result = {'error': 'Key must be 16, 24, or 32 bytes long.'}
        else:
            encrypted = aes_encrypt(text, key)
            decrypted = aes_decrypt(encrypted, key)
            result = {
                'original': text,
                'encrypted': encrypted,
                'decrypted': decrypted
            }
    return render_template('aes.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
