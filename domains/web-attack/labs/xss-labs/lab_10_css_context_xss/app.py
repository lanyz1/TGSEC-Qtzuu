from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/")
def index():
    color = request.args.get("color", "slate")
    return render_template("index.html", color=color)

if __name__ == "__main__":
    app.run(debug=True)