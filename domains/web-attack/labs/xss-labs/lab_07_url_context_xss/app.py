from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/")
def index():
    url = request.args.get("url", "")

    return render_template(
        "index.html",
        url=url
    )

if __name__ == "__main__":
    app.run(debug=True)