from flask import Flask

app = Flask(__name__)


@app.route("/")
def hello():
    return "<!DOCTYPE html><html><head><title>Hello World</title></head><body><h1>Hello from CITADEL</h1><p>Flask is running.</p></body></html>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
