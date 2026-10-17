from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
@app.route("/<path:username>")
def index(username="Guest"):
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)