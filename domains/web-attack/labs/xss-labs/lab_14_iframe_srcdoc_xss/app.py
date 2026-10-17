from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/")
def index():
    content = request.args.get("content", "")
    return render_template("index.html", content=content)

if __name__ == "__main__":
    app.run(debug=True)