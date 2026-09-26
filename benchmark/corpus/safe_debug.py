from flask import Flask
app = Flask(__name__)
if __name__ == "__main__":
    # SAFE: debug off, localhost only
    app.run(debug=False, host="127.0.0.1")
