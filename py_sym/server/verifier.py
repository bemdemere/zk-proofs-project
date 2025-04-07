import subprocess

def verify_proof():
    """Runs ZoKrates proof verification and returns True/False."""
    result = subprocess.run(["zokrates", "verify"], capture_output=True, text=True)
    return "Verification successful" in result.stdout
