## Vault - 7 2.0 [Backend]

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from routes.check_health import check_health_blueprint
from routes.get_token import get_token_blueprint
from routes.file_scan import file_scan_blueprint
from routes.message_scan import message_scan_blueprint
from routes.ip_scan import ip_scan_blueprint
from routes.url_scan import url_scan_blueprint

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your_secret_key'

# Register the health check blueprint
app.register_blueprint(check_health_blueprint)

# Register the token blueprint
app.register_blueprint(get_token_blueprint)

# Register the file scan blueprint
app.register_blueprint(file_scan_blueprint)

# Registered the message scan blueprint
app.register_blueprint(message_scan_blueprint)

# Registered the IP scan blueprint
app.register_blueprint(ip_scan_blueprint)

# Registered the url scan blueprint
app.register_blueprint(url_scan_blueprint)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/docs')
def docs():
    return render_template('docs.html')

@app.route('/test')
def test():
    return render_template('test.html')

@app.route('/test/file_scan')
def test_file_scan():
    return render_template('test_file_scan.html')

@app.route('/test/message_scan')
def test_message_scan():
    return render_template('test_message_scan.html')

@app.route('/test/ip_scan')
def test_ip_scan():
    return render_template('test_ip_scan.html')

@app.route('/test/url_scan')
def test_url_scan():
    return render_template('test_url_scan.html')

if __name__ == '__main__':
    app.run(debug=True)