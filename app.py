from flask import Flask, redirect, url_for
from routes import routes
from database import get_db, close_db, init_db, init_app
import os

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "data.db")

app = Flask(__name__)
app.secret_key = "MekarArmadaJaya"

# register blueprint routes
app.register_blueprint(routes)

# register database teardown handler
init_app(app)

# folder upload
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route("/")
def home():
    return redirect(url_for("routes.login"))

if __name__ == "__main__":
    with app.app_context():
        db = get_db()
        init_db(db)
    app.run(host="0.0.0.0", port=5000, debug=True)
