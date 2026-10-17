from flask import Flask, render_template, request, redirect

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/redirect")
def redirect_user():
    url = request.args.get("url", "/")
    return redirect(url)

if __name__ == "__main__":
    app.run(debug=True)