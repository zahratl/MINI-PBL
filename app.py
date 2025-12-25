from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
# Import Library Kriptografi Baru
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import pymysql
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Menentukan folder upload
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Pastikan folder ada
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

bcrypt = Bcrypt(app)

# --- FUNGSI GENERATE KEY DARI PIN USER ---
def generate_key_from_pin(pin, salt=None):
    """
    Mengubah PIN user menjadi Kunci Fernet 32-byte yang aman.
    """
    if salt is None:
        salt = os.urandom(16) # Buat salt acak 16 byte jika enkripsi baru
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(pin.encode()))
    return key, salt

# Koneksi ke MySQL
def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='',
        database='privatestorage',
        cursorclass=pymysql.cursors.DictCursor
    )

# HALAMAN HOME
@app.route('/')
def home():
    if 'loggedin' in session:
        return redirect(url_for('upload'))
    return render_template('index.html')

# PROSES REGISTER
@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, pw_hash))
        conn.commit()
        cur.close()
        conn.close()
        flash('Registrasi Berhasil! Silakan Login.', 'success')
        return redirect(url_for('home') + "#menu")
    except pymysql.err.IntegrityError:
        flash('Email sudah terdaftar!', 'danger')
        return redirect(url_for('home') + "#register")
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('home') + "#register")

# PROSES LOGIN
@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user and bcrypt.check_password_hash(user['password'], password):
        session['loggedin'] = True
        session['username'] = user['username']
        return redirect(url_for('upload'))
    else:
        flash('Email atau password salah!', 'danger')
        return redirect(url_for('home') + "#menu")

# DASHBOARD UPLOAD
@app.route('/upload')
def upload():
    if 'loggedin' not in session:
        return redirect(url_for('home'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT filename FROM upload")
    files = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('upload.html', nama_user=session['username'], files=files)

# UPLOAD FILE POST
@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'loggedin' not in session:
        return redirect(url_for('home'))
    if 'file' not in request.files:
        return redirect(url_for('upload'))
    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('upload'))

    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO upload (filename) VALUES (%s)", (filename,))
    conn.commit()
    cur.close()
    conn.close()

    flash('File berhasil diupload!', 'success')
    return redirect(url_for('upload'))

# DOWNLOAD FILE
@app.route('/uploads/<filename>')
def download_file(filename):
    if 'loggedin' not in session:
        return redirect(url_for('home'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- ENKRIPSI (LOCK) DENGAN PIN USER ---
@app.route('/encrypt/<filename>', methods=['POST'])
def encrypt_file(filename):
    if 'loggedin' not in session:
        return redirect(url_for('home'))
    
    pin = request.form.get('pin') # Ambil PIN dari Modal
    if not pin:
        flash('PIN diperlukan untuk mengunci file!', 'danger')
        return redirect(url_for('upload'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        # 1. Buat Kunci dari PIN + Salt Baru
        key, salt = generate_key_from_pin(pin)
        cipher = Fernet(key)

        # 2. Baca data asli
        with open(file_path, "rb") as file:
            file_data = file.read()
        
        # 3. Enkripsi
        encrypted_data = cipher.encrypt(file_data)
        
        # 4. Simpan: SALT (16 byte awal) + Data Terenkripsi
        # Kita simpan salt di dalam file supaya nanti bisa dipakai dekripsi
        with open(file_path + ".enc", "wb") as file:
            file.write(salt + encrypted_data)
            
        # 5. Hapus file asli & Update Database
        os.remove(file_path)
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE upload SET filename = %s WHERE filename = %s", (filename + ".enc", filename))
        conn.commit()
        cur.close()
        conn.close()

        flash(f'File terkunci! Ingat PIN anda: {pin}', 'success')
        
    except Exception as e:
        flash(f'Gagal mengenkripsi: {str(e)}', 'danger')

    return redirect(url_for('upload'))

# --- DEKRIPSI (UNLOCK) DENGAN PIN USER ---
@app.route('/decrypt/<filename>', methods=['POST'])
def decrypt_file(filename):
    if 'loggedin' not in session:
        return redirect(url_for('home'))
    
    pin = request.form.get('pin') # Ambil PIN dari Modal
    if not pin:
        flash('PIN diperlukan untuk membuka file!', 'danger')
        return redirect(url_for('upload'))
        
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        # 1. Baca File Terenkripsi
        with open(file_path, "rb") as file:
            full_data = file.read()
        
        # 2. Ambil Salt (16 byte pertama) dan Data
        salt = full_data[:16]
        encrypted_data = full_data[16:]
        
        # 3. Buat Kunci dari PIN User + Salt yg ada di file
        key, _ = generate_key_from_pin(pin, salt)
        cipher = Fernet(key)
        
        # 4. Coba Dekripsi
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # 5. Kembalikan ke file asli
        original_filename = filename.replace('.enc', '')
        original_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
        
        with open(original_path, "wb") as file:
            file.write(decrypted_data)

        # Hapus file .enc & Update Database
        os.remove(file_path)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE upload SET filename = %s WHERE filename = %s", (original_filename, filename))
        conn.commit()
        cur.close()
        conn.close()

        flash(f'File berhasil dibuka! PIN Benar.', 'success')
        
    except InvalidToken:
        flash('PIN SALAH! File tidak dapat dibuka.', 'danger')
    except Exception as e:
        flash(f'Gagal membuka file: {str(e)}', 'danger')

    return redirect(url_for('upload'))

# DELETE FILE
@app.route('/delete/<filename>')
def delete_file(filename):
    if 'loggedin' not in session:
        return redirect(url_for('home'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM upload WHERE filename = %s", (filename,))
    conn.commit()
    cur.close()
    conn.close()

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash(f'File {filename} dihapus.', 'success')
    else:
        flash(f'Data dihapus (file fisik tidak ditemukan).', 'warning')
        
    return redirect(url_for('upload'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)