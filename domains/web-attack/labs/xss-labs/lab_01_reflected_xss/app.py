from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/")
def index():
    query = request.args.get("q", "")
    return render_template("index.html", query=query)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)