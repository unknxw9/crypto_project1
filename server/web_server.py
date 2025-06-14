from flask import Flask, render_template, request, jsonify
import csv
import io

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")  # 前端页面

@app.route("/upload", methods=["POST"])
def upload_csv():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file"}), 400
    # 解析csv
    stream = io.StringIO(file.stream.read().decode("utf-8"))
    reader = csv.reader(stream)
    data = [row for row in reader]
    return jsonify({"rows": data})

if __name__ == "__main__":
    app.run(debug=True)     # flask-web服务器默认是http://127.0.0.1:5000