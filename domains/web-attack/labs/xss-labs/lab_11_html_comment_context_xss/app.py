from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/")
def index():
    comment = request.args.get("comment", "")

    return render_template(
        "index.html",
        comment=comment
    )

if __name__ == "__main__":
    app.run(debug=True)