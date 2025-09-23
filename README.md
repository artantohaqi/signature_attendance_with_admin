Signature Attendance (DTW stroke-based) with Admin Login
-------------------------------------------------------
Features:
- User registration with department and multiple signature samples (vector + thumbnail image)
- Stroke-based matching using DTW
- Attendance records saved; if attendance time > 07:30 server time, client is prompted for 'reason' and reason stored
- Admin panel protected by login (default admin/admin123) to view users, signature thumbnails, and attendance records including reason

How to run:
1. python -m venv venv
2. source venv/bin/activate  (Windows: venv\Scripts\activate)
3. pip install -r requirements.txt
4. python app.py
5. Open http://127.0.0.1:5000 (main page). Admin: http://127.0.0.1:5000/login (use username 'admin' password 'admin123')

Notes:
- Change app.secret_key in app.py for production and change default admin password.
- Threshold for DTW matching is in app.py (0.28) — tune with real enrollment samples.
