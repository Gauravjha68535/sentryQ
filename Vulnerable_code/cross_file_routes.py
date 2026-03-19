# ═══════════════════════════════════════════════════════════════
# TEST FILE: cross_file_routes.py
# EXPECTED: This file is the SOURCE of taint.
# Phase 3A (AI Smart Taint) should trace that user_id from
# request.args flows into db_service.get_user() which is
# defined in cross_file_db.py where it hits a SQL sink.
# ═══════════════════════════════════════════════════════════════

from flask import Flask, request, jsonify
from cross_file_db import get_user, search_users, delete_user

app = Flask(__name__)


@app.route("/api/user")
def api_get_user():
    user_id = request.args.get("id")
    user = get_user(user_id)
    return jsonify(user)


@app.route("/api/search")
def api_search():
    query = request.args.get("q")
    results = search_users(query)
    return jsonify(results)


@app.route("/api/user/delete", methods=["POST"])
def api_delete():
    user_id = request.json.get("id")
    delete_user(user_id)
    return jsonify({"status": "deleted"})


if __name__ == "__main__":
    app.run(debug=True)
