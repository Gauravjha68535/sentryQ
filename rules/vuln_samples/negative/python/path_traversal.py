# NEGATIVE: Safe file access
import os

BASE = "/safe/uploads/"

def serve_file(filename):
    path = os.path.realpath(os.path.join(BASE, filename))
    if not path.startswith(BASE):
        raise ValueError("Path traversal detected")
    open(path, 'r')
