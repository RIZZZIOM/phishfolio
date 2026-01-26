import os
import sys
import uuid
import json
import tempfile
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

# Ensure web directory is in path for local imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from extractor import NestHunterExtractor, ExtractionResult
from analyzer import PatternAnalyzer

# Get the web directory path for templates and static files
WEB_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, 
            template_folder=os.path.join(WEB_DIR, 'templates'),
            static_folder=os.path.join(WEB_DIR, 'static'))
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp(prefix='nesthunter_uploads_')
app.config['SECRET_KEY'] = os.urandom(24)

# Allowed archive extensions
ALLOWED_EXTENSIONS = {
    'zip', 'rar', '7z', 'iso', 'vhd', 'vhdx', 
    'tar', 'gz', 'tgz', 'tar.gz', 'bz2', 'xz'
}

# Store analysis results in memory (for demo - use database in production)
analysis_cache = {}


def allowed_file(filename: str) -> bool:
    """Check if file has allowed extension"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    # Handle double extensions like .tar.gz
    if ext == 'gz' and filename.lower().endswith('.tar.gz'):
        return True
    return ext in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file upload and start analysis"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({
            'error': f'File type not supported. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'
        }), 400
    
    # Get options from request
    max_depth = request.form.get('max_depth', 10, type=int)
    max_depth = min(max(1, max_depth), 20)  # Clamp between 1 and 20
    
    # Save uploaded file
    filename = secure_filename(file.filename)
    unique_id = str(uuid.uuid4())
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{unique_id}_{filename}")
    file.save(upload_path)
    
    try:
        # Initialize extractor and analyzer
        extractor = NestHunterExtractor(max_depth=max_depth)
        analyzer = PatternAnalyzer()
        
        # Perform extraction
        result = extractor.extract(upload_path)
        
        # Analyze for suspicious patterns
        patterns = analyzer.analyze(result)
        analysis_summary = analyzer.get_summary()
        
        # Build response
        response_data = {
            'id': unique_id,
            'filename': filename,
            'extraction': result.to_dict(),
            'analysis': analysis_summary,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Cache result
        analysis_cache[unique_id] = {
            'data': response_data,
            'temp_dir': result.temp_dir,
            'upload_path': upload_path
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        # Clean up on error
        if os.path.exists(upload_path):
            os.remove(upload_path)
        return jsonify({'error': str(e)}), 500


@app.route('/api/analysis/<analysis_id>')
def get_analysis(analysis_id: str):
    """Get cached analysis result"""
    if analysis_id not in analysis_cache:
        return jsonify({'error': 'Analysis not found'}), 404
    
    return jsonify(analysis_cache[analysis_id]['data'])


@app.route('/api/cleanup/<analysis_id>', methods=['POST'])
def cleanup_analysis(analysis_id: str):
    """Clean up analysis files"""
    if analysis_id not in analysis_cache:
        return jsonify({'error': 'Analysis not found'}), 404
    
    cache_entry = analysis_cache[analysis_id]
    
    try:
        # Remove temporary extraction directory
        import shutil
        if cache_entry.get('temp_dir') and os.path.exists(cache_entry['temp_dir']):
            shutil.rmtree(cache_entry['temp_dir'], ignore_errors=True)
        
        # Remove uploaded file
        if cache_entry.get('upload_path') and os.path.exists(cache_entry['upload_path']):
            os.remove(cache_entry['upload_path'])
        
        # Remove from cache
        del analysis_cache[analysis_id]
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/export/<analysis_id>')
def export_analysis(analysis_id: str):
    """Export analysis as JSON"""
    if analysis_id not in analysis_cache:
        return jsonify({'error': 'Analysis not found'}), 404
    
    data = analysis_cache[analysis_id]['data']
    response = app.response_class(
        response=json.dumps(data, indent=2),
        status=200,
        mimetype='application/json'
    )
    response.headers['Content-Disposition'] = f'attachment; filename=nesthunter_report_{analysis_id[:8]}.json'
    return response


@app.route('/api/stats')
def get_stats():
    """Get current session stats"""
    return jsonify({
        'active_analyses': len(analysis_cache),
        'supported_formats': list(ALLOWED_EXTENSIONS)
    })


@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 500MB'}), 413


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


# Cleanup on shutdown
import atexit
import shutil

def cleanup_on_exit():
    """Clean up all temporary files on exit"""
    for analysis_id, cache_entry in list(analysis_cache.items()):
        try:
            if cache_entry.get('temp_dir') and os.path.exists(cache_entry['temp_dir']):
                shutil.rmtree(cache_entry['temp_dir'], ignore_errors=True)
            if cache_entry.get('upload_path') and os.path.exists(cache_entry['upload_path']):
                os.remove(cache_entry['upload_path'])
        except:
            pass
    
    if os.path.exists(app.config['UPLOAD_FOLDER']):
        shutil.rmtree(app.config['UPLOAD_FOLDER'], ignore_errors=True)

atexit.register(cleanup_on_exit)


if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                      NestHunter                           ║
    ║         Nested Archive Extraction & Analysis Tool         ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    print(f"  Upload folder: {app.config['UPLOAD_FOLDER']}")
    print(f"  Max file size: 500MB")
    print(f"  Supported formats: {', '.join(ALLOWED_EXTENSIONS)}")
    print()
    
    app.run(debug=True, host='127.0.0.1', port=5000)
