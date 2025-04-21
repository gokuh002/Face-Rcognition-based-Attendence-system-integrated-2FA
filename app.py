from flask import Flask, render_template, request, redirect, url_for, session, Response, jsonify, send_file, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
import pyotp
import qrcode
import io
import bcrypt
import csv
import datetime

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User model for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, otp_secret):
        self.id = id
        self.username = username
        self.otp_secret = otp_secret

@login_manager.user_loader
def load_user(user_id):
    """Loads the user from users.db when Flask-Login needs it."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, otp_secret FROM users WHERE id=?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[2])
    return None

# **Register Route**
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        otp_secret = pyotp.random_base32()  # Generate a unique 2FA secret key

        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password, otp_secret) VALUES (?, ?, ?)",
                           (username, hashed_password, otp_secret))
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists. Try a different one.", "danger")
            return redirect(url_for('register'))
        finally:
            conn.close()

        return redirect(url_for('show_qr', username=username))

    return render_template('register.html')

# **Show QR Code After Registration**
@app.route('/show_qr/<username>')
def show_qr(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT otp_secret FROM users WHERE username=?", (username,))
    user_data = cursor.fetchone()
    conn.close()

    if not user_data:
        return "User not found!", 404

    otp_secret = user_data[0]
    totp = pyotp.TOTP(otp_secret)
    uri = totp.provisioning_uri(name=username, issuer_name="Attendance App")

    return render_template('show_qr.html', qr_uri=uri, username=username)

# **Login Route (Now with Error Messages)**
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, otp_secret FROM users WHERE username=?", (username,))
        user_data = cursor.fetchone()
        conn.close()

        if not user_data:
            flash("User not registered. Please sign up.", "danger")
            return redirect(url_for('login'))

        if not bcrypt.checkpw(password, user_data[2]):  # Verify password
            flash("Incorrect password. Please try again.", "danger")
            return redirect(url_for('login'))

        user = User(user_data[0], user_data[1], user_data[3])
        login_user(user)
        return redirect(url_for('verify_otp'))

    return render_template('login.html')

# **OTP Verification Route**
@app.route('/verify_otp', methods=['GET', 'POST'])
@login_required
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        totp = pyotp.TOTP(current_user.otp_secret)

        if totp.verify(otp):  # Check if OTP is correct
            session['authenticated'] = True
            return redirect(url_for('index'))  # Redirect to home page after successful verification

        flash("Invalid OTP, please try again.", "danger")

    return render_template('verify_otp.html')

# **Generate QR Code for 2FA**
@app.route('/generate_qr')
@login_required
def generate_qr():
    totp = pyotp.TOTP(current_user.otp_secret)
    uri = totp.provisioning_uri(name=current_user.username, issuer_name="Attendance App")

    qr = qrcode.make(uri)
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    
    return Response(img_io.getvalue(), mimetype='image/png')

# **Home Page**
@app.route('/')
@login_required
def index():
    return render_template('index.html')

# **Attendance Fetch Route (Fixed "Not Found" Error)**
@app.route('/attendance', methods=['POST'])
@login_required
def attendance():
    selected_date = request.form.get('selected_date')

    if not selected_date:
        flash("Please select a date.", "danger")
        return redirect(url_for('index'))

    conn = sqlite3.connect("attendance.db")
    cursor = conn.cursor()
    
    cursor.execute("SELECT name, time FROM attendance WHERE date = ?", (selected_date,))
    attendance_data = cursor.fetchall()
    
    conn.close()

    return render_template('index.html', selected_date=selected_date, attendance_data=attendance_data, no_data=not bool(attendance_data))

# **Download CSV Route (Fixed "Not Found" Error)**
@app.route('/download_csv')
@login_required
def download_csv():
    selected_date = request.args.get('selected_date')

    if not selected_date:
        flash("Date not provided.", "danger")
        return redirect(url_for('index'))

    conn = sqlite3.connect("attendance.db")
    cursor = conn.cursor()

    cursor.execute("SELECT name, time FROM attendance WHERE date = ?", (selected_date,))
    attendance_data = cursor.fetchall()
    
    conn.close()

    if not attendance_data:
        flash("No attendance data found for this date.", "warning")
        return redirect(url_for('index'))

    # Create CSV file in memory
    output = io.StringIO()
    csv_writer = csv.writer(output)
    
    csv_writer.writerow(["Name", "Time"])
    csv_writer.writerows(attendance_data)
    
    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=attendance_{selected_date}.csv"}
    )

# **Logout Route**
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('authenticated', None)
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
