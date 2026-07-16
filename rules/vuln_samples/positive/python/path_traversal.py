# POSITIVE: Path traversal
from flask import request
import os

def serve_file():
    filename = request.args.get('file')
    # Unsafe: direct open with user input
    open(filename, 'r')
    open("/uploads/" + filename, 'r')
    open(f"/static/{filename}", 'r')
