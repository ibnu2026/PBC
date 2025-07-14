# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import smtplib, ssl
import sqlite3
import os
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'rahasia123'
s = URLSafeTimedSerializer(app.secret_key)

# Konfigurasi email pengirim
EMAIL_SENDER = 'ahmadibnuzaini2026@gmail.com'
EMAIL_PASSWORD = 'ygjycarflzsnumwa'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 465

# Konfigurasi upload
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Inisialisasi database
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nama TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_verified INTEGER DEFAULT 0,
        foto TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS pendaftaran (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        nama_kursus TEXT,
        tanggal TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()
init_db()

# Kirim email verifikasi
def kirim_email_verifikasi(email):
    token = s.dumps(email, salt='email-verify')
    link = url_for('verifikasi_email', token=token, _external=True)
    subject = "Verifikasi Email Anda"
    body = f"Silakan klik link berikut untuk verifikasi akun Anda:\n{link}"
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, email, f"Subject: {subject}\n\n{body}")

@app.route('/')
def root():
    return redirect(url_for('index'))

@app.route('/index')
def index():
    nama = session.get('nama')
    foto = session.get('foto')
    return render_template('index.html', nama=nama, foto=foto)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nama = request.form['nama']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (nama, email, password) VALUES (?, ?, ?)", (nama, email, password))
            conn.commit()
            conn.close()
            kirim_email_verifikasi(email)
            flash('Pendaftaran berhasil! Silakan cek email Anda untuk verifikasi.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email sudah terdaftar.', 'danger')
    return render_template('register.html')

@app.route('/verify/<token>')
def verifikasi_email(token):
    try:
        email = s.loads(token, salt='email-verify', max_age=3600)
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
        conn.commit()
        conn.close()
        flash('Email Anda berhasil diverifikasi. Silakan login.', 'success')
    except Exception:
        flash('Link verifikasi tidak valid atau kadaluarsa.', 'danger')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT id, nama, password, is_verified, foto FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        if user:
            if user[3] == 0:
                flash('Akun belum diverifikasi. Silakan cek email Anda.', 'danger')
            elif check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['nama'] = user[1]
                session['foto'] = user[4] or url_for('static', filename='default.png')
                return redirect(url_for('index'))
            else:
                flash('Password salah.', 'danger')
        else:
            flash('Email tidak ditemukan.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/profil', methods=['GET', 'POST'])
def profil():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    user_id = session['user_id']
    if request.method == 'POST':
        nama = request.form['nama']
        file = request.files.get('foto')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            foto_path = url_for('static', filename=f'uploads/{filename}')
            c.execute("UPDATE users SET nama = ?, foto = ? WHERE id = ?", (nama, foto_path, user_id))
            session['foto'] = foto_path
        else:
            c.execute("UPDATE users SET nama = ? WHERE id = ?", (nama, user_id))
        session['nama'] = nama
        conn.commit()
        flash('Profil berhasil diperbarui.', 'success')
    c.execute("SELECT nama, email, foto FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    return render_template('profil.html', user=user)

@app.route('/daftar', methods=['GET', 'POST'])
def daftar():
    if 'user_id' not in session:
        flash('Silakan login terlebih dahulu untuk mendaftar kursus.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        nama_kursus = request.form['kursus']
        user_id = session['user_id']
        tanggal = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO pendaftaran (user_id, nama_kursus, tanggal) VALUES (?, ?, ?)", (user_id, nama_kursus, tanggal))
        conn.commit()
        conn.close()

        flash('Pendaftaran kursus berhasil!', 'success')
        return redirect(url_for('infopendaftaran'))

    return render_template('daftar.html')


@app.route('/infopendaftaran')
def infopendaftaran():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT users.nama, pendaftaran.nama_kursus, pendaftaran.tanggal
                 FROM pendaftaran
                 JOIN users ON pendaftaran.user_id = users.id
                 ORDER BY pendaftaran.tanggal DESC''')
    data = c.fetchall()
    conn.close()
    return render_template('infopendaftaran.html', data=data)

if __name__ == '__main__':
    app.run(debug=True)
