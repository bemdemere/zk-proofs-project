from flask import Flask, request, jsonify, send_from_directory
import json
import subprocess
import os

app = Flask(__name__)
USER_DB = "users.json"

# Create users.json if missing
if not os.path.exists(USER_DB):
    with open(USER_DB, "w") as f:
        json.dump({}, f)

@app.route("/")
def serve_index():
    return send_from_directory(".", "index.html")

@app.route("/zk/<path:path>")
def serve_artifacts(path):
    return send_from_directory("zk", path)

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    stored_hash = data["stored_hash"]

    with open(USER_DB, "r") as f:
        users = json.load(f)

    users[username] = {
        "stored_hash": stored_hash
    }

    with open(USER_DB, "w") as f:
        json.dump(users, f)

    return "Registered!"


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    inputs = data["inputs"]
    proof = data["proof"]

    # Load registered users
    with open(USER_DB, "r") as f:
        users = json.load(f)

    if username not in users:
        return "User not found", 404

    user_data = users[username]
    expected_stored_hash = list(map(str, user_data["stored_hash"]))
    print("Received stored hash from input:", inputs[-2:])
    print("Expected stored hash from DB:", expected_stored_hash)

    # Validate the last 2 inputs match stored_hash
    flat_inputs = [item for sublist in inputs for item in (sublist if isinstance(sublist, list) else [sublist])]
    if flat_inputs[-2:] != expected_stored_hash:
        return "Hash mismatch: invalid credentials", 403


    # Save proof and inputs for ZoKrates
    os.makedirs("client", exist_ok=True)
    with open("client/proof.json", "w") as f:
        json.dump(proof, f)
    with open("client/input.txt", "w") as f:
        f.write(" ".join(flat_inputs) + "\n")

    # Run ZoKrates verify
    result = subprocess.run(
        ["/usr/local/bin/zokrates", "verify", "-j", "client/proof.json", "-i", "client/input.txt", "-v", "zk/verification.key"],
        capture_output=True, text=True
    )

    print("ZoKrates Output:\n", result.stdout)
    print("ZoKrates Error:\n", result.stderr)

    if "PASSED" in result.stdout:
        return f"Login successful for {username}"
    else:
        return "Invalid proof", 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)  # Changed to 0.0.0.0