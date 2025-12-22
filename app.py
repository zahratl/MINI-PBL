from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet # Import library enkripsi
import pymysql
import os



app = Flask(__name__)
app.secret_key = os.urandom(24)

# Menentukan folder upload. Pastikan folder ini ada!
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- SETUP KUNCI ENKRIPSI ---
# Cek apakah file kunci sudah ada, jika belum, buat baru.
if not os.path.exists("secret.key"):
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Muat kunci agar bisa dipakai
def load_key():
    return open("secret.key", "rb").read()

key = load_key()
cipher = Fernet(key)
# -----------------------------

bcrypt = Bcrypt(app)

# Koneksi ke MySQL (XAMPP)
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

    # Enkripsi password
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, pw_hash))
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

# UPLOAD HALAMAN GET (DASHBOARD)
@app.route('/upload')
def upload():
    if 'loggedin' not in session:
        return redirect(url_for('home'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT filename FROM upload") # Pastikan nama tabel benar 'upload'
    files = cur.fetchall()
    cur.close()
    conn.close()

    return render_template(
        'upload.html',
        nama_user=session['username'],
        files=files
    )

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

    # simpan ke folder
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    # simpan ke database
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO upload (filename) VALUES (%s)",
        (filename,)
    )
    conn.commit()
    cur.close()
    conn.close()

    flash('File berhasil diupload!', 'success')
    return redirect(url_for('upload'))

# --- FITUR BARU: DOWNLOAD / BUKA FILE ---
@app.route('/uploads/<filename>')
def download_file(filename):
    if 'loggedin' not in session:
        return redirect(url_for('home'))
        
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- FITUR BARU: ENKRIPSI (LOCK) ---
@app.route('/encrypt/<filename>')
def encrypt_file(filename):
    if 'loggedin' not in session:
        return redirect(url_for('home'))
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        # Baca data asli
        with open(file_path, "rb") as file:
            file_data = file.read()
        
        # Enkripsi data
        encrypted_data = cipher.encrypt(file_data)
        
        # Timpa file dengan data terenkripsi
        with open(file_path, "wb") as file:
            file.write(encrypted_data)
            
        flash(f'File {filename} berhasil dikunci (LOCKED)! 🔒', 'success')
        
    except Exception as e:
        flash(f'Gagal mengenkripsi: {str(e)}', 'danger')

    return redirect(url_for('upload'))

# --- FITUR BARU: DESKRIPSI (UNLOCK) ---
@app.route('/decrypt/<filename>')
def decrypt_file(filename):
    if 'loggedin' not in session:
        return redirect(url_for('home'))
        
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        # Baca data terenkripsi
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        
        # Deskripsi data
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # Timpa file dengan data asli
        with open(file_path, "wb") as file:
            file.write(decrypted_data)

        flash(f'File {filename} berhasil dibuka (UNLOCKED)! 🔓', 'success')
        
    except Exception as e:
        flash('Gagal membuka file! Mungkin file belum dikunci atau kunci salah.', 'danger')

    return redirect(url_for('upload'))

#DELETE FILE
@app.route('/delete/<filename>')
def delete_file(filename):
    if 'loggedin' not in session:
        return redirect(url_for('home'))

    # 1. Hapus dari Database dulu
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM upload WHERE filename = %s", (filename,))
    conn.commit()
    cur.close()
    conn.close()

    # 2. Hapus File Fisik
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if os.path.exists(file_path):
        os.remove(file_path)
        flash(f'File {filename} berhasil dihapus permanen!', 'success')
    else:
        # Jika file fisik sudah tidak ada (misal terhapus manual), tidak apa-apa
        # karena database sudah dibersihkan.
        flash(f'Data file {filename} dihapus dari database (file fisik tidak ditemukan).', 'warning')
        
    # 3. Redirect ke halaman dashboard (upload), BUKAN upload_file
    return redirect(url_for('upload'))

# LOGOUT
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)