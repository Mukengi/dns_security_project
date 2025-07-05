from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello():
    return "It works!"

app.run(debug=True)

