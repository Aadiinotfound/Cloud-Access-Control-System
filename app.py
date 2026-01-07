from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime, timezone
import json

# =========================
# 🔹 Initialize Flask App
# =========================
app = Flask(__name__)
CORS(app)

# =========================
# 🔹 Firebase Setup
# =========================
cred = credentials.Certificate("serviceAccount.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

# =========================
# 🔹 Routes
# =========================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# =========================
# 🔹 Verify Login & Log Data
# =========================
@app.route("/verify", methods=["POST"])
def verify():
    try:
        data = request.get_json()
        email = data.get("email")
        ip = data.get("ip")
        country = data.get("country", "Unknown")
        device_info = data.get("device_info", {})
        threat = data.get("threat", None)

        # =========================
        # ✅ Device Info Parser
        # =========================
        def parse_device_info(info):
            if not isinstance(info, dict):
                return {"raw": str(info)}

            return {
                "os": info.get("os", "-"),
                "browser": info.get("browser", "-"),
                "language": info.get("language", "-"),
                "screen": info.get("screen", "-"),
                "uid": info.get("uid", "-"),
                "fingerprint": info.get("fingerprint", "-")
            }

        # =========================
        # ✅ Log Entry Creation
        # =========================
        log_data = {
            "email": email,
            "ip": ip,
            "country": country,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "Success",
            "device_info": parse_device_info(device_info),
            "threat": threat if threat else "Safe",
        }

        db.collection("login_attempts").add(log_data)
        print(f"✅ Log saved: {log_data}")

        return jsonify({"message": "Login success!", "redirect": "/dashboard"}), 200

    except Exception as e:
        print("❌ Error in /verify:", e)
        return jsonify({"message": str(e)}), 500


# =========================
# 🔹 Dashboard Data API
# =========================
@app.route("/api/stats", methods=["GET"])
def get_stats():
    try:
        docs = db.collection("login_attempts").stream()

        total = success = blocked = 0
        countries = {}
        logs = []

        for doc in docs:
            d = doc.to_dict()
            total += 1
            if d.get("status") == "Success":
                success += 1
            else:
                blocked += 1

            c = d.get("country", "Unknown")
            countries[c] = countries.get(c, 0) + 1

            logs.append(d)

        return jsonify({
            "total": total,
            "success": success,
            "blocked": blocked,
            "countries": countries,
            "logs": logs
        }), 200

    except Exception as e:
        print("❌ Error in /api/stats:", e)
        return jsonify({"error": str(e)}), 500


# =========================
# 🔹 Logs Endpoint
# =========================
@app.route("/api/logs", methods=["GET"])
def get_logs():
    try:
        docs = db.collection("login_attempts").order_by(
            "timestamp", direction=firestore.Query.DESCENDING).limit(20).stream()
        logs = [doc.to_dict() for doc in docs]
        return jsonify({"logs": logs}), 200
    except Exception as e:
        print("❌ Error fetching logs:", e)
        return jsonify({"error": str(e)}), 500


# =========================
# 🔹 Run the App
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5500, debug=True)















