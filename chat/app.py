import os
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import chat  # your chat.py module

load_dotenv()

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(
    __name__,
    template_folder="../UI/templates",
    static_folder="../UI/static"
)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
def chat_route():
    data = request.get_json(force=True)
    user_message = data.get('message', '')
    try:
        ai_response = chat.chat_text(user_message)
    except Exception as e:
        ai_response = "Sorry, I am unable to generate a response."
    return jsonify({"response": ai_response})

@app.route('/upload', methods=['POST'])
def upload_files():
    if 'files' not in request.files:
        return jsonify({"error": "No files part in the request"}), 400

    uploaded_files = request.files.getlist('files')
    saved_files = []

    # Deduplicate file paths by filename
    filenames_seen = set()
    for file in uploaded_files:
        filename = secure_filename(file.filename)
        if filename in filenames_seen:
            continue  # skip duplicates
        filenames_seen.add(filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        file.save(save_path)
        saved_files.append(save_path)

    results = chat.chat_files(saved_files)

    # Normalize results
    formatted_results = []
    for r in results:
        formatted_results.append({
            "file": r.get("file"),
            "language": r.get("language", "Unknown"),
            "line_count": r.get("line_count"),
            "file_size": r.get("file_size"),
            "severity_summary": r.get("severity_summary", {}),
            "findings": r.get("findings", [{"note": "No obvious issues found."}])
        })

    return jsonify({"results": formatted_results})

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
