from flask import Flask, render_template, redirect, url_for, request, send_file,flash
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import InputRequired, Length, ValidationError
import sqlite3
from hashlib import md5
from Crypto.Cipher import DES3,AES
import tempfile
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from hashlib import sha256
import os
from werkzeug.utils import secure_filename
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisisasecretkey'

# Initialize Bcrypt and LoginManager
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Helper function to get a database connection
def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  # Allow columns to be accessed by name
    return conn

# Define the User class for managing login sessions
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    @staticmethod
    def get(user_id):
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM user WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['password'])
        return None

# Form for registration
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM user WHERE username = ?', (username.data,))
        existing_user = cursor.fetchone()
        conn.close()
        if existing_user:
            raise ValidationError("The username already exists, please choose a different one.")

# Form for login
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM user WHERE username = ?', (form.username.data,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data and bcrypt.check_password_hash(user_data['password'], form.password.data):
            user = User(user_data['id'], user_data['username'], user_data['password'])
            login_user(user)
            return redirect(url_for('services'))
        else:
            form.password.errors.append('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO user (username, password) VALUES (?, ?)', (form.username.data, hashed_password))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)
@app.route('/services')
@login_required
def services():
    return render_template('services.html')

@app.route('/service1', methods=['GET'])
@login_required
def service1():
    return render_template('service1.html')

@app.route('/service2', methods=['GET', 'POST'])
@login_required
def service2():
    if request.method == 'POST':
        operation = request.form.get('operation')
        key_file = request.files.get('key_file')
        data_file = request.files.get('data_file')

        if operation == 'generate':
            key = RSA.generate(2048)
            private_key = key.export_key(format='PEM')
            public_key = key.publickey().export_key(format='PEM')

            os.makedirs("keys", exist_ok=True)
            with open("keys/private.pem", "wb") as f:
                f.write(private_key)
            with open("keys/public.pem", "wb") as f:
                f.write(public_key)

            flash("RSA Keys generated and saved in keys/ directory.")

        elif operation == 'encrypt' and key_file and data_file:
            key_file.seek(0)
            key_data = key_file.read()

            if not key_data:
                flash("Public key file is empty.")
                return redirect(request.url)

            try:
                public_key = RSA.import_key(key_data)
            except (ValueError, IndexError, TypeError) as e:
                flash(f"Failed to load public key: {str(e)}")
                return redirect(request.url)

            session_key = get_random_bytes(16)
            cipher_aes = AES.new(session_key, AES.MODE_CBC)
            data_file.seek(0)
            ciphertext = cipher_aes.encrypt(pad(data_file.read(), AES.block_size))

            cipher_rsa = PKCS1_OAEP.new(public_key)
            encrypted_session_key = cipher_rsa.encrypt(session_key)

            ext = os.path.splitext(data_file.filename)[1]
            output_filename = f"encrypted{ext}"
            with open(output_filename, "wb") as out:
                out.write(encrypted_session_key)
                out.write(cipher_aes.iv)
                out.write(ciphertext)

            return send_file(output_filename, as_attachment=True)

        elif operation == 'decrypt' and key_file and data_file:
            key_file.seek(0)
            key_data = key_file.read()

            if not key_data:
                flash("Private key file is empty.")
                return redirect(request.url)

            try:
                private_key = RSA.import_key(key_data)
            except (ValueError, IndexError, TypeError) as e:
                flash(f"Failed to load private key: {str(e)}")
                return redirect(request.url)

            with tempfile.NamedTemporaryFile(delete=False) as temp:
                temp.write(data_file.read())
                temp.flush()
                with open(temp.name, 'rb') as f:
                    encrypted_session_key = f.read(256)
                    iv = f.read(16)
                    ciphertext = f.read()

            try:
                cipher_rsa = PKCS1_OAEP.new(private_key)
                session_key = cipher_rsa.decrypt(encrypted_session_key)
                cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
                plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
            except Exception as e:
                flash(f"Decryption failed: {str(e)}")
                return redirect(request.url)

            ext = os.path.splitext(data_file.filename)[1]
            output_filename = f"decrypted{ext}"
            with open(output_filename, 'wb') as out:
                out.write(plaintext)

            return send_file(output_filename, as_attachment=True)

    return render_template("service2.html")


@app.route('/service3', methods=['GET', 'POST'])
@login_required
def service3():
    return render_template('service3.html')

@app.route('/hash_file', methods=['POST'])
@login_required
def hash_file():
    if 'file' not in request.files:
        flash('No file uploaded')
        return redirect(url_for('service3'))

    file = request.files['file']
    data = file.read()
    hash_result = sha256(data).hexdigest()

    return render_template('service3.html', hash_result=hash_result)

@app.route('/compare_hashes', methods=['POST'])
@login_required
def compare_hashes():
    if 'file1' not in request.files or 'file2' not in request.files:
        flash('Both files are required')
        return redirect(url_for('service3'))

    file1 = request.files['file1']
    file2 = request.files['file2']
    hash1 = sha256(file1.read()).hexdigest()
    hash2 = sha256(file2.read()).hexdigest()

    if hash1 == hash2:
        result = "✅ Files are identical (hashes match)."
    else:
        result = "❌ Files are different (hashes do not match)."

    return render_template('service3.html', comparison_result=result)


@app.route('/service1/3des', methods=['GET', 'POST'])
@login_required
def service1_3des():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        key = request.form['key']
        operation = request.form['operation']

        file_bytes = uploaded_file.read()
        key_hash = md5(key.encode('ascii')).digest()
        tdes_key = DES3.adjust_key_parity(key_hash)

        cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')

        if operation == 'encrypt':
            result_bytes = cipher.encrypt(file_bytes)
        else:
            result_bytes = cipher.decrypt(file_bytes)

        # Write result to temp file and send back to user
        temp = tempfile.NamedTemporaryFile(delete=False)
        temp.write(result_bytes)
        temp.seek(0)

        filename = f"{'encrypted' if operation == 'encrypt' else 'decrypted'}_{uploaded_file.filename}"
        return send_file(temp.name, as_attachment=True, download_name=filename)

    return render_template('des.html')

def derive_key(password, salt, key_size=16):
    return PBKDF2(password, salt, dkLen=key_size, count=100_000)


@app.route('/aes', methods=['GET', 'POST'])
@login_required
def aes():
    if request.method == 'POST':
        operation = request.form['operation']
        mode = request.form['mode']
        key_size = int(request.form['key_size'])
        password = request.form['password']
        iv_input = request.form['iv_input']
        file = request.files['input_file']

        if file and password and iv_input:
            try:
                data = file.read()

                if operation == 'encrypt':
                    salt = os.urandom(16)
                    key = derive_key(password.encode(), salt, key_size // 8)
                    iv = sha256(iv_input.encode()).digest()[:16]

                    if mode == 'EAX':
                        cipher = AES.new(key, AES.MODE_EAX, nonce=iv)
                        ciphertext, tag = cipher.encrypt_and_digest(data)
                        result = salt + tag + ciphertext
                    elif mode == 'CBC':
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                        ciphertext = cipher.encrypt(pad(data, AES.block_size))
                        result = salt + ciphertext

                elif operation == 'decrypt':
                    salt = data[:16]
                    encrypted_data = data[16:]
                    key = derive_key(password.encode(), salt, key_size // 8)
                    iv = sha256(iv_input.encode()).digest()[:16]

                    if mode == 'EAX':
                        tag = encrypted_data[:16]
                        ciphertext = encrypted_data[16:]
                        cipher = AES.new(key, AES.MODE_EAX, nonce=iv)
                        result = cipher.decrypt_and_verify(ciphertext, tag)

                    elif mode == 'CBC':
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                        result = unpad(cipher.decrypt(encrypted_data), AES.block_size)

                # Save result to a temporary file
                temp = tempfile.NamedTemporaryFile(delete=False)
                temp.write(result)
                temp.flush()
                temp.seek(0)

                filename = f"{'encrypted' if operation == 'encrypt' else 'decrypted'}_{file.filename}"
                return send_file(temp.name, as_attachment=True, download_name=filename)

            except ValueError as ve:
                flash(f"Decryption error: {ve}")
                return redirect(url_for('aes'))

            except Exception as e:
                flash(f"An error occurred: {str(e)}")
                return redirect(url_for('aes'))

    return render_template('aes.html')
@app.route('/steganography', methods=['GET', 'POST'])
@login_required
def steganography():
    if request.method == 'POST':
        mode = request.form['mode']
        skip = int(request.form['skip'])
        pattern = list(map(int, request.form['pattern'].split(',')))
        carrier = request.files['carrier']

        if mode == 'embed':
            target = request.files['target']
            carrier_data = bytearray(carrier.read())
            target_data = target.read()
            bits = ''.join(f"{byte:08b}" for byte in target_data)
            index = skip
            pattern_index = 0

            for bit in bits:
                if index >= len(carrier_data):
                    break
                carrier_data[index] = (carrier_data[index] & 0b11111110) | int(bit)
                index += pattern[pattern_index]
                pattern_index = (pattern_index + 1) % len(pattern)

            output_ext = os.path.splitext(carrier.filename)[1]
            temp = tempfile.NamedTemporaryFile(delete=False, suffix=output_ext)
            temp.write(carrier_data)
            temp.seek(0)

            return send_file(temp.name, as_attachment=True, download_name="embedded" + output_ext)

        elif mode == 'extract':
            size = int(request.form['size'])
            ext = request.form['ext'].strip()
            if not ext.startswith('.'):
                ext = '.' + ext

            carrier_data = bytearray(carrier.read())
            bits = ''
            index = skip
            pattern_index = 0
            bit_count = size * 8

            for _ in range(bit_count):
                if index >= len(carrier_data):
                    break
                bits += str(carrier_data[index] & 1)
                index += pattern[pattern_index]
                pattern_index = (pattern_index + 1) % len(pattern)

            byte_data = bytearray(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))

            temp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
            temp.write(byte_data)
            temp.seek(0)

            return send_file(temp.name, as_attachment=True, download_name="recovered" + ext)

    return render_template('steg.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

if __name__ == '__main__':
    # Create tables in SQLite if they don't exist already
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ Tables created successfully!")  # Confirm that tables are created
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

