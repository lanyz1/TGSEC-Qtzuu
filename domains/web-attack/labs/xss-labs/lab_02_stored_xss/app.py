from flask import Flask, request, render_template

app = Flask(__name__)

messages = []

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        message = request.form.get("message", "")
        messages.append(message)

    return render_template("index.html", messages=messages)


if __name__ == "__main__":
    app.run(debug=True)