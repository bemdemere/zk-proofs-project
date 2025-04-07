from flask import Flask, request, jsonify
import subprocess
import json
import os
from verifier import verify_proof

app = Flask(__name__)

# Load user-graph data from JSON file
with open("graph_data.json", "r") as file:
    user_graphs = json.load(file)

@app.route('/login', methods=['POST'])
def zk_login():
    """Handles authentication request using zero-knowledge proof"""
    data = request.json
    username = data.get("username")
    colors = data.get("colors")
    
    if username not in user_graphs:
        return jsonify({"success": False, "error": "User not found"}), 400

    # Retrieve graph edges for the user
    edges = user_graphs[username]["edges"]

    # Convert inputs to space-separated strings for ZoKrates CLI
    colors_str = " ".join(map(str, colors))
    edges_str = " ".join(" ".join(map(str, edge)) for edge in edges)

    try:
        # Compute the witness
        subprocess.run(["zokrates", "compute-witness", "-a"] + colors_str.split() + edges_str.split(), check=True)

        # Generate a proof
        subprocess.run(["zokrates", "generate-proof"], check=True)

    except subprocess.CalledProcessError:
        return jsonify({"success": False, "error": "Invalid credentials or proof generation failed"}), 400

    # Verify the proof
    is_valid = verify_proof()

    if is_valid:
        return jsonify({"success": True, "message": "Authentication successful (ZKP verified)!"})
    else:
        return jsonify({"success": False, "message": "Authentication failed (invalid proof)!"})

if __name__ == '__main__':
    app.run(debug=True)
