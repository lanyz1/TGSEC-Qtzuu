#!/usr/bin/env python3
"""
Flask Web Application for JavaScript Security Analyzer
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
from analyzer import JavaScriptAnalyzer
import json
import uuid
import os
from typing import List, Dict

app = Flask(__name__)
CORS(app)

# Get the base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

analyzer = JavaScriptAnalyzer()

# Store analysis results in memory (in production, use Redis or database)
analysis_results = {}


@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Analyze single or multiple JavaScript files
    
    ALL ANALYSIS IS PERFORMED ON THE SERVER - NOT IN THE BROWSER
    - JavaScript files are fetched by the server
    - Pattern matching and analysis happens server-side
    - Only results are sent back to the browser
    """
    try:
        if request.is_json:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Invalid JSON in request body'}), 400
            
            urls = data.get('urls', [])
            if isinstance(urls, str):
                urls = [urls]
            
            if not urls:
                url = data.get('url', '').strip()
                if url:
                    urls = [url]
            
            if not urls:
                return jsonify({'error': 'URL(s) are required'}), 400
        else:
            # Handle file upload
            if 'file' in request.files:
                file = request.files['file']
                if file.filename:
                    content = file.read().decode('utf-8')
                    urls = [line.strip() for line in content.split('\n') if line.strip() and not line.strip().startswith('#')]
                    if not urls:
                        return jsonify({'error': 'No valid URLs found in file'}), 400
                else:
                    return jsonify({'error': 'No file uploaded'}), 400
            else:
                return jsonify({'error': 'No file or JSON data provided'}), 400
        
        # Generate session ID for this batch
        session_id = str(uuid.uuid4())
        analysis_results[session_id] = {
            'files': [],
            'total': len(urls),
            'completed': 0
        }
        
        # Start analysis (ALL PROCESSING HAPPENS ON SERVER)
        # The analyzer fetches JS files, runs regex patterns, and processes results server-side
        results = []
        for idx, url in enumerate(urls):
            url = url.strip()
            if not url:
                continue
            
            try:
                # Server-side analysis: fetch file, run patterns, extract findings
                result = analyzer.analyze(url)
                result_dict = {
                    'file_id': idx + 1,
                    'url': result.url,
                    'api_keys': result.api_keys or [],
                    'credentials': result.credentials or [],
                    'emails': result.emails or [],
                    'interesting_comments': result.interesting_comments or [],
                    'xss_vulnerabilities': result.xss_vulnerabilities or [],
                    'xss_functions': result.xss_functions or [],
                    'api_endpoints': result.api_endpoints or [],
                    'parameters': result.parameters or [],
                    'paths_directories': result.paths_directories or [],
                    'errors': result.errors or [],
                    'file_size': result.file_size,
                    'analysis_timestamp': result.analysis_timestamp,
                }
                results.append(result_dict)
                analysis_results[session_id]['files'].append(result_dict)
                analysis_results[session_id]['completed'] += 1
            except Exception as e:
                import traceback
                traceback.print_exc()
                error_result = {
                    'file_id': idx + 1,
                    'url': url,
                    'errors': [f'Analysis failed: {str(e)}'],
                    'api_keys': [],
                    'credentials': [],
                    'emails': [],
                    'interesting_comments': [],
                    'xss_vulnerabilities': [],
                    'xss_functions': [],
                    'api_endpoints': [],
                    'parameters': [],
                    'paths_directories': [],
                    'file_size': 0,
                    'analysis_timestamp': '',
                }
                results.append(error_result)
                analysis_results[session_id]['files'].append(error_result)
                analysis_results[session_id]['completed'] += 1
        
        return jsonify({
            'session_id': session_id,
            'total_files': len(results),
            'results': results
        })
    
    except Exception as e:
        import traceback
        error_msg = str(e)
        traceback.print_exc()
        return jsonify({'error': error_msg}), 500


@app.route('/api/results/<session_id>', methods=['GET'])
def get_results(session_id):
    """Get analysis results for a session"""
    if session_id not in analysis_results:
        return jsonify({'error': 'Session not found'}), 404
    
    session_data = analysis_results[session_id]
    return jsonify(session_data)


@app.route('/api/file/<session_id>/<int:file_id>', methods=['GET'])
def get_file_result(session_id, file_id):
    """Get specific file result"""
    if session_id not in analysis_results:
        return jsonify({'error': 'Session not found'}), 404
    
    files = analysis_results[session_id]['files']
    file_result = next((f for f in files if f.get('file_id') == file_id), None)
    
    if not file_result:
        return jsonify({'error': 'File not found'}), 404
    
    return jsonify(file_result)


@app.route('/<path:filename>')
def serve_file(filename):
    """
    Serve JavaScript files from the project root for testing
    This route must be LAST (after all API routes) to avoid route conflicts.
    Example: http://192.168.1.15:5000/test.js
    """
    # Only serve .js files for security
    # Skip if it's an API route, static files, or templates
    if filename.startswith('api/') or filename.startswith('static/') or filename.startswith('templates/'):
        return jsonify({'error': 'Not found'}), 404
    
    if filename.endswith('.js'):
        try:
            return send_from_directory(BASE_DIR, filename, mimetype='application/javascript')
        except FileNotFoundError:
            return jsonify({'error': f'File {filename} not found'}), 404
    
    return jsonify({'error': 'File not found'}), 404


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

