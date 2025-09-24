from flask import Blueprint, render_template, request, session, redirect, url_for, g, jsonify
import sqlite3, json
from datetime import datetime, time
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db
from signature_utils import preprocess_signature, dtw_distance
from werkzeug.utils import secure_filename
import os
import logging

# Konfigurasi logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

routes = Blueprint('routes', __name__)
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@routes.route("/upload")
def upload_page():
    return render_template("upload.html")

@routes.route("/api/upload", methods=["POST"])
def api_upload():
    email = request.form.get("email", "").strip().lower()
    signature = request.form.get("signature", None)
    files = request.files.getlist("files")

    logging.info(f"[UPLOAD] Request received for email: '{email}'.")

    if not email or signature is None or not files:
        logging.warning("[UPLOAD] Request failed: missing email, signature, or files.")
        return jsonify({"ok": False, "error": "email, signature, and files are required"}), 400

    db = get_db()
    cur = db.cursor()
    timestamp_dt = datetime.now()
    timestamp = timestamp_dt.isoformat()

    cur.execute("SELECT id, departement_id FROM users WHERE email = ?", (email,))
    row = cur.fetchone()

    if not row:
        logging.error(f"[UPLOAD] Failed for email '{email}': user not registered. Logging to DB.")
        cur.execute("""INSERT INTO uploads
            (user_id, departement_id, email, files, status, note, distance)
            VALUES (?,?,?,?,?,?,?)""",
            (None, None, email, None, "failed", "user not registered", None))
        db.commit()
        return jsonify({"ok": False, "error": "user not registered"}), 404

    user_id, departement_id = row
    logging.info(f"[UPLOAD] User '{email}' (ID: {user_id}) found. Proceeding to signature validation.")

    cur.execute("SELECT sig_json FROM signatures WHERE user_id = ?", (user_id,))
    rows = cur.fetchall()
    if not rows:
        logging.warning(f"[UPLOAD] Failed for user '{email}': no reference signatures found. Logging to DB.")
        cur.execute("""INSERT INTO uploads
            (user_id, departement_id, email, files, status, note, distance)
            VALUES (?,?,?,?,?,?,?)""",
            (user_id, departement_id, email, None, "failed", "no reference signatures", None))
        db.commit()
        return jsonify({"ok": False, "error": "no reference signatures"}), 400

    try:
        input_json = json.loads(signature)
        input_pts = preprocess_signature(input_json, n=150)
    except Exception as e:
        logging.error(f"[UPLOAD] Failed for user '{email}': Invalid signature format. Detail: {str(e)}")
        return jsonify({"ok": False, "error": "invalid signature format", "detail": str(e)}), 400

    distances = []
    for (sig_json_str,) in rows:
        try:
            ref_json = json.loads(sig_json_str)
            ref_pts = preprocess_signature(ref_json, n=150)
            d = dtw_distance(ref_pts, input_pts)
            distances.append(d)
        except Exception:
            logging.warning(f"[UPLOAD] Skipping a corrupted reference signature for user '{email}'.")
            continue

    if not distances:
        logging.error(f"[UPLOAD] Failed for user '{email}': Processing error (no valid reference signatures). Logging to DB.")
        cur.execute("""INSERT INTO uploads
            (user_id, departement_id, email, files, status, note, distance)
            VALUES (?,?,?,?,?,?,?)""",
            (user_id, departement_id, email, None, "failed", "processing error", None))
        db.commit()
        return jsonify({"ok": False, "error": "processing error"}), 500

    min_dist = float(min(distances))
    threshold = 0.10

    if min_dist > threshold:
        attempted_names = [f.filename for f in files]
        logging.warning(f"[UPLOAD] Rejected for user '{email}': signature mismatch (distance={min_dist:.4f}). Logging to DB.")
        cur.execute("""INSERT INTO uploads
            (user_id, departement_id, email, files, status, note, distance)
            VALUES (?,?,?,?,?,?,?)""",
            (user_id, departement_id, email, json.dumps(attempted_names), "failed",
             f"signature mismatch (distance={min_dist:.4f})", min_dist))
        db.commit()
        return jsonify({"ok": False, "error": "signature mismatch", "distance": min_dist}), 403

    saved_files = []
    for f in files:
        if f and f.filename:
            filename = secure_filename(f.filename)
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            f.save(save_path)
            saved_files.append(filename)
    
    logging.info(f"[UPLOAD] Files {saved_files} successfully saved for user '{email}'.")

    cur.execute("""INSERT INTO uploads
        (user_id, departement_id, email, files, status, note, distance)
        VALUES (?,?,?,?,?,?,?)""",
        (user_id, departement_id, email, json.dumps(saved_files), "success",
         f"signature match (distance={min_dist:.4f})", min_dist))
    db.commit()

    logging.info(f"[UPLOAD] Successful for user '{email}'. Distance: {min_dist:.4f}.")
    return jsonify({
        "ok": True,
        "status": "success",
        "note": f"signature match (distance={min_dist:.4f})",
        "files": saved_files,
        "distance": min_dist
    })
    
# --- Error Handlers JSON ---
@routes.errorhandler(404)
def not_found(e):
    logging.warning(f"404 Not Found: {request.path}")
    return jsonify({"ok": False, "error": "not found"}), 404

@routes.errorhandler(405)
def method_not_allowed(e):
    logging.warning(f"405 Method Not Allowed: {request.method} on {request.path}")
    return jsonify({"ok": False, "error": "method not allowed"}), 405

@routes.errorhandler(500)
def server_error(e):
    logging.critical(f"500 Internal Server Error: {str(e)}", exc_info=True)
    return jsonify({"ok": False, "error": "internal server error", "detail": str(e)}), 500

# --- Dekorator untuk admin ---
def require_admin(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get('admin_id'):
            logging.warning(f"[ACCESS] Unauthorized access attempt to {request.path}")
            return redirect(url_for('routes.login'))
        return fn(*a, **kw)
    return wrapped

# --- Rute Halaman ---
@routes.route("/")
def home():
    return redirect(url_for('routes.login'))

@routes.route("/register")
def register_page():
    return render_template("register.html")

@routes.route("/attendance")
def attendance_page():
    return render_template("attendance.html")

@routes.route("/departement")
@require_admin
def departement_page():
    db = get_db()
    cur = db.cursor()
    departements = cur.execute("SELECT id, departement FROM departements ORDER BY departement ASC").fetchall()
    return render_template("departement.html", departements=departements)

@routes.route("/absensi")
@require_admin
def absensi_page():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT a.id, a.user_id, a.email, a.timestamp, a.status, a.distance, a.reason, d.departement FROM attendance a LEFT JOIN departements d ON a.departement_id = d.id ORDER BY a.timestamp DESC")
    attendance = cur.fetchall()
    return render_template("absensi.html", attendance=attendance, admin_username=session.get('admin_username'))

# --- Rute API ---
@routes.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    nama_lengkap = data.get("nama_lengkap","").strip()
    email = data.get("email","").strip().lower()
    signatures = data.get("signatures", [])
    logging.info(f"[REGISTER] Request received for email: '{email}'.")
    if not nama_lengkap or not email or not signatures or not isinstance(signatures, list):
        logging.warning("[REGISTER] Failed: missing nama_lengkap, email, or signatures.")
        return jsonify({"ok": False, "error": "nama_lengkap, email, and signatures[] required (min 1)"}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO users (nama_lengkap, email, created_at) VALUES (?,?,?)",
                    (nama_lengkap, email, datetime.utcnow().isoformat()))
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        logging.error(f"[REGISTER] Failed for '{email}': email already registered.")
        return jsonify({"ok": False, "error": "email already registered"}), 400
    for sig in signatures:
        cur.execute("INSERT INTO signatures (user_id, sig_json, created_at) VALUES (?,?,?)",
                    (user_id, json.dumps(sig), datetime.utcnow().isoformat()))
    db.commit()
    logging.info(f"[REGISTER] User '{email}' (ID: {user_id}) registered successfully.")
    return jsonify({"ok": True})

@routes.route("/api/attendance", methods=["POST"])
def api_attendance():
    data = request.get_json()
    email = data.get("email","").strip().lower()
    signature = data.get("signature", None)
    reason = data.get("reason", "").strip()

    logging.info(f"[ATTENDANCE] Request received for email: '{email}'.")

    if not email or signature is None:
        logging.warning("[ATTENDANCE] Request failed: missing email or signature.")
        return jsonify({"ok": False, "error":"email and signature required"}), 400

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, nama_lengkap, departement_id FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    timestamp_dt = datetime.now()
    timestamp = timestamp_dt.isoformat()

    if not row:
        logging.error(f"[ATTENDANCE] Failed for email '{email}': user not registered. Logging to DB.")
        cur.execute("INSERT INTO attendance (user_id,email,timestamp,status,note,distance,reason,departement_id) VALUES (?,?,?,?,?,?,?,?)",
                    (None, email, timestamp, "failed", "user not registered", None, None, None))
        db.commit()
        return jsonify({"ok": False, "error":"user not registered"}), 404

    user_id, nama_lengkap, departement_id = row
    logging.info(f"[ATTENDANCE] User '{email}' (ID: {user_id}) found.")

    cur.execute("SELECT sig_json FROM signatures WHERE user_id = ?", (user_id,))
    rows = cur.fetchall()
    if not rows:
        logging.warning(f"[ATTENDANCE] Failed for user '{email}': no reference signatures. Logging to DB.")
        cur.execute("INSERT INTO attendance (user_id,email,timestamp,status,note,distance,reason,departement_id) VALUES (?,?,?,?,?,?,?,?)",
                    (user_id, email, timestamp, "failed", "no reference signatures", None, None, departement_id))
        db.commit()
        return jsonify({"ok": False, "error":"no reference signatures"}), 400

    try:
        input_pts = preprocess_signature(signature, n=150)
    except Exception as e:
        logging.error(f"[ATTENDANCE] Failed for user '{email}': Invalid signature format. Detail: {str(e)}")
        return jsonify({"ok": False, "error":"invalid signature format", "detail": str(e)}), 400
    
    distances = []
    for (sig_json_str,) in rows:
        try:
            ref_json = json.loads(sig_json_str)
            ref_pts = preprocess_signature(ref_json, n=150)
            d = dtw_distance(ref_pts, input_pts)
            distances.append(d)
        except Exception:
            logging.warning(f"[ATTENDANCE] Skipping a corrupted reference signature for user '{email}'.")
            continue
            
    if not distances:
        logging.error(f"[ATTENDANCE] Failed for user '{email}': Processing error (no valid reference signatures). Logging to DB.")
        cur.execute("INSERT INTO attendance (user_id,email,timestamp,status,note,distance,reason,departement_id) VALUES (?,?,?,?,?,?,?,?)",
                    (user_id, email, timestamp, "failed", "processing error", None, None, departement_id))
        db.commit()
        return jsonify({"ok": False, "error":"processing error"}), 500

    min_dist = float(min(distances))
    threshold = 0.10
    cutoff = time(7,30,0)
    is_late = timestamp_dt.time() > cutoff
    
    if is_late and not reason:
        logging.warning(f"[ATTENDANCE] User '{email}' is late ({timestamp_dt.time().strftime('%H:%M:%S')}) but no reason provided.")
        return jsonify({"ok": False, "need_reason": True, "note": f"late (time {timestamp_dt.time().strftime('%H:%M:%S')})"}), 200

    if min_dist <= threshold:
        status = "success"
        note = f"signature match (distance={min_dist:.4f})"
        ok = True
        logging.info(f"[ATTENDANCE] Successful for user '{email}'. Distance: {min_dist:.4f}.")
        if is_late:
            logging.warning(f"[ATTENDANCE] User '{email}' is late ({timestamp_dt.time().strftime('%H:%M:%S')}). Reason: '{reason}'.")
    else:
        status = "failed"
        note = f"signature mismatch (distance={min_dist:.4f})"
        ok = False
        logging.warning(f"[ATTENDANCE] Failed for user '{email}': signature mismatch (distance={min_dist:.4f}).")

    cur.execute("INSERT INTO attendance (user_id,email,timestamp,status,note,distance,reason,departement_id) VALUES (?,?,?,?,?,?,?,?)",
                (user_id, email, timestamp, status, note, min_dist, reason if is_late else None, departement_id))
    db.commit()
    
    return jsonify({"ok": ok, "status": status, "note": note, "name": nama_lengkap, "distance": min_dist, "late": is_late})

# --- Tambahan rute lainnya (tanpa logging, untuk singkatnya) ---
@routes.route("/api/list_users")
def api_list_users():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT u.id, u.nama_lengkap, u.email, d.departement FROM users u JOIN departements d ON u.departement_id = d.id ORDER BY u.nama_lengkap ASC")
    rows = cur.fetchall()
    users = [{"id": r[0], "nama_lengkap": r[1], "email": r[2], "departement": r[3]} for r in rows]
    return jsonify({"users":users})

@routes.route("/api/departements")
def api_departements():
    db = get_db()
    cur = db.cursor()
    departements = cur.execute("SELECT id, departement FROM departements ORDER BY departement ASC").fetchall()
    return jsonify({"departements": [{"id": d[0], "departement": d[1]} for d in departements]})

@routes.route("/api/add_department", methods=["POST"])
@require_admin
def api_add_department():
    data = request.get_json()
    departement_name = data.get("departement", "").strip()
    if not departement_name:
        return jsonify({"ok": False, "error": "Departement name required"}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO departements (departement) VALUES (?)", (departement_name,))
        db.commit()
        return jsonify({"ok": True, "message": "Departement added successfully"})
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "Departement already exists"}), 400
    
@routes.route('/api/edit_department', methods=['POST'])
@require_admin
def api_edit_department():
    data = request.json
    id = data.get('id')
    name = data.get('name')
    if not id or not name:
        return jsonify({'ok': False, 'error': 'ID dan nama departemen tidak boleh kosong.'}), 400
    
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE departements SET departement = ? WHERE id = ?", (name, id))
        db.commit()
        if cursor.rowcount == 0:
            return jsonify({'ok': False, 'error': 'Departemen tidak ditemukan.'}), 404
        return jsonify({'ok': True, 'message': 'Departemen berhasil diperbarui.'})
    except Exception as e:
        db.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 500

@routes.route('/api/delete_department/<int:dept_id>', methods=['DELETE'])
@require_admin
def api_delete_department(dept_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM departements WHERE id = ?", (dept_id,))
        db.commit()
        if cursor.rowcount == 0:
            return jsonify({'ok': False, 'error': 'Departemen tidak ditemukan.'}), 404
        return jsonify({'ok': True, 'message': 'Departemen berhasil dihapus.'})
    except Exception as e:
        db.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 500

@routes.route("/api/add_admin", methods=["POST"])
@require_admin
def api_add_admin():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password are required"}), 400
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)))
        db.commit()
        return jsonify({"ok": True, "message": "Admin added successfully"})
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "Username already exists"}), 400

@routes.route("/api/edit_admin", methods=["POST"])
@require_admin
def api_edit_admin():
    data = request.get_json()
    admin_id = data.get("id")
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not admin_id or not username:
        return jsonify({"ok": False, "error": "Admin ID and username are required"}), 400
    db = get_db()
    cur = db.cursor()
    try:
        if password:
            cur.execute("UPDATE admins SET username = ?, password_hash = ? WHERE id = ?",
                        (username, generate_password_hash(password), admin_id))
        else:
            cur.execute("UPDATE admins SET username = ? WHERE id = ?",
                        (username, admin_id))
        db.commit()
        return jsonify({"ok": True, "message": "Admin updated successfully"})
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "Username already exists"}), 400

@routes.route("/api/delete_admin/<int:admin_id>", methods=["DELETE"])
@require_admin
def api_delete_admin(admin_id):
    if admin_id == session.get('admin_id'):
        return jsonify({"ok": False, "error": "You cannot delete your own account"}), 403
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM admins WHERE id = ?", (admin_id,))
    db.commit()
    return jsonify({"ok": True, "message": "Admin deleted successfully"})

@routes.route('/api/edit_user', methods=['POST'])
@require_admin
def api_edit_user():
    data = request.json
    user_id = data.get('id')
    fullname = data.get('fullname')
    email = data.get('email')
    departement_id = data.get('departement_id')

    if not user_id or not fullname or not email or not departement_id:
        return jsonify({'ok': False, 'error': 'Data tidak lengkap.'}), 400

    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE users SET nama_lengkap = ?, email = ?, departement_id = ? WHERE id = ?", (fullname, email, departement_id, user_id))
        db.commit()
        if cursor.rowcount == 0:
            return jsonify({'ok': False, 'error': 'Pengguna tidak ditemukan.'}), 404
        return jsonify({'ok': True, 'message': 'Data pengguna berhasil diperbarui.'})
    except Exception as e:
        db.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 500

@routes.route('/api/delete_user/<int:user_id>', methods=['DELETE'])
@require_admin
def api_delete_user(user_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM signatures WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        if cursor.rowcount == 0:
            return jsonify({'ok': False, 'error': 'Pengguna tidak ditemukan.'}), 404
        return jsonify({'ok': True, 'message': 'Pengguna dan data tanda tangan berhasil dihapus.'})
    except Exception as e:
        db.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 500

@routes.route("/api/get_signatures/<int:user_id>", methods=["GET"])
@require_admin
def api_get_signatures(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, sig_json FROM signatures WHERE user_id = ?", (user_id,))
    signatures = cur.fetchall()
    
    sig_list = []
    for sig_id, sig_json_str in signatures:
        try:
            sig_data = json.loads(sig_json_str)
            sig_list.append({"id": sig_id, "sig_json": sig_data})
        except (json.JSONDecodeError, TypeError):
            continue
    
    return jsonify({"ok": True, "signatures": sig_list})

@routes.route("/api/delete_signature/<int:sig_id>", methods=["DELETE"])
@require_admin
def api_delete_signature(sig_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM signatures WHERE id = ?", (sig_id,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"ok": False, "error": "Tanda tangan tidak ditemukan."}), 404
    return jsonify({"ok": True, "message": "Tanda tangan berhasil dihapus."})

@routes.route("/api/add_signature", methods=["POST"])
@require_admin
def api_add_signature():
    data = request.get_json()
    user_id = data.get("user_id")
    signature = data.get("signature")
    
    if not user_id or not signature:
        return jsonify({"ok": False, "error": "user_id dan signature diperlukan"}), 400

    db = get_db()
    cur = db.cursor()
    
    cur.execute("INSERT INTO signatures (user_id, sig_json, created_at) VALUES (?, ?, ?)",
                (user_id, json.dumps(signature), datetime.utcnow().isoformat()))
    db.commit()
    return jsonify({"ok": True, "message": "Tanda tangan berhasil ditambahkan."})

@routes.route("/api/update_signatures/<int:user_id>", methods=["POST"])
@require_admin
def api_update_signatures(user_id):
    data = request.get_json()
    signatures = data.get("signatures", [])
    
    if not signatures or len(signatures) < 3 or not isinstance(signatures, list):
        return jsonify({"ok": False, "error": "Minimal 3 signatures diperlukan"}), 400

    db = get_db()
    cur = db.cursor()
    
    try:
        cur.execute("DELETE FROM signatures WHERE user_id = ?", (user_id,))
        
        for sig in signatures:
            cur.execute("INSERT INTO signatures (user_id, sig_json, created_at) VALUES (?, ?, ?)",
                        (user_id, json.dumps(sig), datetime.utcnow().isoformat()))
        
        db.commit()
        return jsonify({"ok": True, "message": "Tanda tangan berhasil diupdate."})
    except Exception as e:
        db.rollback()
        return jsonify({"ok": False, "error": str(e)}), 500

@routes.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT COUNT(*) FROM admins")
        if cur.fetchone()[0] == 0:
            cur.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                        ("admin", generate_password_hash("password")))
            db.commit()

        cur.execute("SELECT id, username, password_hash FROM admins WHERE username = ?", (username,))
        row = cur.fetchone()
        
        if row and check_password_hash(row[2], password):
            session['admin_id'] = row[0]
            session['admin_username'] = row[1]
            logging.info(f"Admin '{username}' logged in successfully.")
            return redirect(url_for("routes.admin_panel"))
        
        logging.warning(f"Failed login attempt for username: '{username}'.")
        return render_template("login.html", error="Invalid credentials")
    
    return render_template("login.html")

@routes.route("/logout")
def logout():
    logging.info(f"Admin '{session.get('admin_username')}' logged out.")
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    return redirect(url_for("routes.login"))

@routes.route("/admin")
@require_admin
def admin_panel():
    db = get_db()
    cur = db.cursor()
    
    cur.execute("SELECT id, username, password_hash FROM admins")
    admins = cur.fetchall()
    
    cur.execute("SELECT u.id, u.nama_lengkap, u.email, d.departement FROM users u JOIN departements d ON u.departement_id = d.id ORDER BY u.id DESC")
    users = cur.fetchall()
    
    return render_template("admin.html", admins=admins, users=users, admin_username=session.get('admin_username'))