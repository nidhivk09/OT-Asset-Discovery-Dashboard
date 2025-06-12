from flask import Flask, jsonify, request, render_template, send_from_directory
import json
from scan import AdvancedOTScanner
app = Flask(__name__)

scanner=AdvancedOTScanner()
@app.route('/')
def index():
    return render_template('index.html')


@app.route("/start-scan", methods=["POST"])
def start_scan():
    data = request.get_json()
    subnet = data.get("subnet")
    if not subnet:
        return jsonify({"error": "No subnet provided"}), 400

    try:
        results = scanner.run_comprehensive_scan(subnet)  # 👈 your function here
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500




if __name__ == "__main__":
    app.run(debug=True,port=5001)
# or any unused port
