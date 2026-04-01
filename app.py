import os
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and file.filename.endswith('.eml'):
        # Pass to parsing logic
        return jsonify({'message': 'File received, parsing is to be implemented.'})
        
    return jsonify({'error': 'Invalid file format. Please upload a .eml file.'}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)
