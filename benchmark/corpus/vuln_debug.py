from flask import Flask
app = Flask(__name__)
if __name__ == "__main__":
    # VULN: debug mode in production entrypoint
    app.run(debug=True, host="0.0.0.0")
