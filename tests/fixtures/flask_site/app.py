"""
Minimal multi-page site for crawl accuracy harness (static HTML only).
"""
from __future__ import annotations

from flask import Flask, Response

app = Flask(__name__)


@app.route("/")
def index() -> str:
    return """<!doctype html><html><body>
<h1>home</h1>
<p><a href="/page2">page2</a></p>
<p><a href="/page3">page3</a></p>
<p><a href="/disallowed/secret" rel="nofollow">nofollow link</a></p>
</body></html>"""


@app.route("/page2")
def page2() -> str:
    return """<!doctype html><html><body>
<h1>p2</h1>
<p><a href="/formpage">formpage</a></p>
</body></html>"""


@app.route("/page3")
def page3() -> str:
    return "<html><body><h1>p3</h1></body></html>"


@app.route("/formpage")
def formpage() -> str:
    return """<!doctype html><html><body>
<form action="/submit" method="post">
  <input type="text" name="q" />
  <button type="submit">go</button>
</form>
</body></html>"""


@app.route("/submit", methods=["POST"])
def submit() -> str:
    return "ok"


@app.route("/robots.txt")
def robots() -> Response:
    body = "User-agent: boomStick\nDisallow: /disallowed/\nUser-agent: *\nDisallow: /disallowed/\n"
    return Response(body, mimetype="text/plain")


@app.route("/disallowed/secret")
def disallowed_secret() -> str:
    return "should-not-be-crawled"

