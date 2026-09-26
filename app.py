"""Linker - a password-locked link vault.

One Flask process serves the UI and does the crypto; there is no separate
frontend or backend to run. Passwords are kept in memory only, for the life of
an unlocked session, and never written to disk or into a cookie.
"""

import os
import secrets
import socket
import time
import uuid
from urllib.parse import urlparse

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import vault

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IDLE_TIMEOUT = 30 * 60  # seconds a collection stays unlocked without activity

app = Flask(__name__)


def _secret_key():
    """Persist a signing key so sessions survive a restart."""
    path = os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(key)
    os.chmod(path, 0o600)
    return key


app.secret_key = _secret_key()
app.config.update(SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_HTTPONLY=True)

# sid -> {slug: {"password": str, "touched": float}}
# Lives in the process only: restarting the server locks everything again.
_UNLOCKED = {}


def _sid():
    if "sid" not in session:
        session["sid"] = secrets.token_urlsafe(24)
    return session["sid"]


def _keyring():
    return _UNLOCKED.setdefault(_sid(), {})


def _unlock(slug, password):
    _keyring()[slug] = {"password": password, "touched": time.time()}


def _password_for(slug):
    """Return the live password for a slug, expiring idle unlocks."""
    entry = _keyring().get(slug)
    if not entry:
        return None
    if time.time() - entry["touched"] > IDLE_TIMEOUT:
        _keyring().pop(slug, None)
        return None
    entry["touched"] = time.time()
    return entry["password"]


def _lock(slug):
    _keyring().pop(slug, None)


def _require_password(slug):
    password = _password_for(slug)
    if password is None:
        abort(redirect(url_for("collection", slug=slug)))
    return password


def normalize_url(raw):
    """Accept 'example.com' and turn it into something clickable."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""
    return raw


@app.template_filter("host")
def host_filter(url):
    try:
        return urlparse(url).netloc or url
    except ValueError:
        return url


@app.route("/")
def index():
    collections = vault.list_collections()
    unlocked = {slug for slug in list(_keyring()) if _password_for(slug)}
    return render_template("index.html", collections=collections, unlocked=unlocked)


@app.route("/create", methods=["POST"])
def create():
    name = request.form.get("name", "").strip()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")

    if not name:
        flash("Give the collection a name.", "error")
    elif len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
    elif password != confirm:
        flash("The two passwords do not match.", "error")
    else:
        try:
            slug = vault.create(name, password)
        except vault.VaultError as exc:
            flash(str(exc), "error")
        else:
            _unlock(slug, password)
            flash("Collection created and unlocked.", "ok")
            return redirect(url_for("collection", slug=slug))
    return redirect(url_for("index"))


@app.route("/c/<slug>")
def collection(slug):
    if not vault.exists(slug):
        abort(404)
    password = _password_for(slug)
    if password is None:
        return render_template("unlock.html", slug=slug)
    try:
        data = vault.read(slug, password)
    except vault.BadPassword:
        _lock(slug)
        return render_template("unlock.html", slug=slug)
    query = request.args.get("q", "").strip().lower()
    links = data.get("links", [])
    if query:
        links = [
            l
            for l in links
            if query in l.get("name", "").lower()
            or query in l.get("url", "").lower()
            or query in l.get("note", "").lower()
        ]
    return render_template(
        "collection.html", slug=slug, data=data, links=links, query=query
    )


@app.route("/c/<slug>/unlock", methods=["POST"])
def unlock(slug):
    if not vault.exists(slug):
        abort(404)
    password = request.form.get("password", "")
    try:
        vault.read(slug, password)
    except vault.BadPassword:
        flash("Wrong password.", "error")
        return render_template("unlock.html", slug=slug), 401
    _unlock(slug, password)
    return redirect(url_for("collection", slug=slug))


@app.route("/c/<slug>/lock", methods=["POST"])
def lock(slug):
    _lock(slug)
    flash("Collection locked.", "ok")
    return redirect(url_for("index"))


@app.route("/lock-all", methods=["POST"])
def lock_all():
    _UNLOCKED.pop(_sid(), None)
    flash("Everything locked.", "ok")
    return redirect(url_for("index"))


@app.route("/c/<slug>/links", methods=["POST"])
def add_link(slug):
    password = _require_password(slug)
    name = request.form.get("name", "").strip()
    url = normalize_url(request.form.get("url", ""))
    note = request.form.get("note", "").strip()

    if not name or not url:
        flash("A link needs a name and a valid http(s) address.", "error")
        return redirect(url_for("collection", slug=slug))

    data = vault.read(slug, password)
    data.setdefault("links", []).append(
        {
            "id": uuid.uuid4().hex,
            "name": name,
            "url": url,
            "note": note,
            "added": vault._now(),
        }
    )
    vault.save(slug, data, password)
    flash("Link saved.", "ok")
    return redirect(url_for("collection", slug=slug))


@app.route("/c/<slug>/links/<link_id>/edit", methods=["POST"])
def edit_link(slug, link_id):
    password = _require_password(slug)
    name = request.form.get("name", "").strip()
    url = normalize_url(request.form.get("url", ""))
    note = request.form.get("note", "").strip()

    if not name or not url:
        flash("A link needs a name and a valid http(s) address.", "error")
        return redirect(url_for("collection", slug=slug))

    data = vault.read(slug, password)
    for link in data.get("links", []):
        if link["id"] == link_id:
            link.update(name=name, url=url, note=note)
            break
    else:
        abort(404)
    vault.save(slug, data, password)
    flash("Link updated.", "ok")
    return redirect(url_for("collection", slug=slug))


@app.route("/c/<slug>/links/<link_id>/delete", methods=["POST"])
def delete_link(slug, link_id):
    password = _require_password(slug)
    data = vault.read(slug, password)
    before = len(data.get("links", []))
    data["links"] = [l for l in data.get("links", []) if l["id"] != link_id]
    if len(data["links"]) == before:
        abort(404)
    vault.save(slug, data, password)
    flash("Link removed.", "ok")
    return redirect(url_for("collection", slug=slug))


@app.route("/c/<slug>/password", methods=["POST"])
def change_password(slug):
    current = request.form.get("current", "")
    new = request.form.get("new", "")
    confirm = request.form.get("confirm", "")

    if len(new) < 8:
        flash("New password must be at least 8 characters.", "error")
    elif new != confirm:
        flash("The two new passwords do not match.", "error")
    else:
        try:
            vault.change_password(slug, current, new)
        except vault.BadPassword:
            flash("Current password is wrong.", "error")
        else:
            _unlock(slug, new)
            flash("Password changed. The file was re-encrypted.", "ok")
    return redirect(url_for("collection", slug=slug))


@app.route("/c/<slug>/delete", methods=["POST"])
def delete_collection(slug):
    password = request.form.get("password", "")
    try:
        vault.delete(slug, password)
    except vault.BadPassword:
        flash("Wrong password - collection not deleted.", "error")
        return redirect(url_for("collection", slug=slug))
    except vault.CollectionMissing:
        abort(404)
    _lock(slug)
    flash("Collection deleted.", "ok")
    return redirect(url_for("index"))


@app.errorhandler(404)
def not_found(_exc):
    return render_template("404.html"), 404


def lan_ip():
    """Best guess at this machine's LAN address; no packets are actually sent."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f" * Local:   http://127.0.0.1:{port}")
    if host == "0.0.0.0":
        print(f" * Network: http://{lan_ip()}:{port}")
    app.run(host=host, port=port, debug=False)
