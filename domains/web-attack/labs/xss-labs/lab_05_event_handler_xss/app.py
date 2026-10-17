from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/")
def index():
    message = request.args.get("message", "")

    return render_template(
        "index.html",
        message=message
    )

if __name__ == "__main__":
    app.run(debug=True)