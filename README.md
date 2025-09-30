# Chat LLM BitNet Vulnerability Analyzer

**Chat** is a local code vulnerability analyzer that uses both **heuristic checks** and an optional **dataset-based matching** system to identify potential security issues in code. It supports multiple programming languages and can scan individual files, entire folders, or code snippets.

This tool is designed to help developers and security researchers quickly detect common vulnerabilities such as SQL injection, buffer overflows, unsafe file handling, and insecure coding patterns.

---

## Features

* Supports multiple languages: Python, C, C++, Java, JavaScript, PHP, Shell, Go, and Rust.
* Detects vulnerabilities using **heuristic checks**:

  * SQL Injection
  * Plaintext password storage
  * Unsafe use of `eval`, `exec`, or system commands
  * Hardcoded credentials
  * Unsafe file handling
* Optional **dataset-based matching** against a JSONL dataset for known code patterns.
* Logs analysis results to `chat_log.txt`.
* Supports analyzing:

  * Single files
  * Entire directories recursively
  * Direct code snippets

---

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourname/Machine_Learning_Project.git
   cd Machine_Learning_Project
   ```
2. Ensure you have Python 3 installed.
3. Install required packages (if any):

   ```bash
   pip install -r requirements.txt
   ```
4. (Optional) Add your dataset in `vuln_dataset.jsonl` for dataset-based matching.

## Usage

# 3 diffrent types of use:
1. Docker LLM (using chat1.py or chat2.py)
2. Web Page Application
3. Terminal Application (similar to Docker)

------------------------------------------------------------------------------------------------------------------
# Docker LLM (using chat1.py or chat2.py)

First run:


```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce-cli
```
Then open your Docker_for_Desktop Application so that the contianer can be built.

After run:
```bash
docker build -t newest .
docker run -it --rm bitnet:latest
```
You should now be in the container. You can type "chat" to see what flags are avalable for you


------------------------------------------------------------------------------------------------------------------
# Web Page Application

run "python3 chat/app.py"

You will then see in the terminal that a url is being generated for your local host to run the webpage. There you can uploads your files and have the AI scan them for vunlerablilites. 

------------------------------------------------------------------------------------------------------------------
# Terminal Application (similar to Docker)

Analyze a single file:

```bash
python3 chat.py -f path/to/file.py
```

Analyze an entire folder:

```bash
python chat.py -f path/to/folder/
```

Analyze a code snippet directly:

```bash
python chat.py -p "some code snippet or keywords"
```

View analysis log:

```bash
python chat.py --view-log
```

Clear the log:

```bash
python chat.py --clear-log
```

---

## Output Example

```json
{
  "language": "Java",
  "method": "heuristics",
  "findings": [
    {
      "type": "Plaintext password storage",
      "description": "Storing passwords in plaintext is unsafe.",
      "fix": "Hash passwords before storing (bcrypt or similar).",
      "line": 8
    },
    {
      "type": "SQL Injection risk",
      "description": "User input concatenated into SQL string can lead to SQL injection.",
      "fix": "Use PreparedStatement instead of concatenation.",
      "line": 34
    }
  ]
}
```

---

## Project Structure

```
Machine_Learning_Project/
├─ Dockerfile                 # Main Docker build configuration for containerizing the app
├─ Dockerfile2.txt            # Alternate/experimental Dockerfile (possibly for testing variations)
├─ README.md                  # Project documentation (Markdown version)
├─ Scripts/                   # Helper scripts or automation utilities
├─ UI/                        # Local user interface files (desktop or CLI-based UI)
├─ User_Interface_WebSite/    # Frontend/backend code for the web-based interface
├─ code_samples/              # Vulnerable and safe code samples used for AI training/learning
├─ candidates.jsonl           # Stores candidate vulnerability patterns detected by AI
├─ chat/                      # Core chat + analyzer package (chat.py, app.py, utilities)
├─ chat1.py                   # Alternate version of chat analyzer script (used for offline Docker LLM with your Dataset)
├─ chat2.py                   # Another alternate/testing version of chat analyzer script (Used for Online Docker LLM with other LLM Dataset)
├─ chat_log.jsonl             # Log of all scans and their findings
├─ dist/                      # Distribution/compiled output (for packaging the project)
├─ pip-25.2.dist-info/        # Python package metadata (installed with pip)
├─ requirements.txt           # Python dependencies required to run the project
├─ rulepack_autoupdated.json  # Dynamic rulepack updated by AI self-learning system
├─ stuff/                     # Miscellaneous files (uncategorized utilities/tests)
├─ tests/                     # Test files for validating analyzer functionality
├─ uploads/                   # User-uploaded files for analysis (via web app or UI)
├─ vuln_dataset.csv           # Vulnerability dataset in CSV format (easy to read)
├─ vuln_dataset.jsonl         # Vulnerability dataset in JSONL format (used by AI engine)
├─ yaml_files/                # YAML configuration files for rulepacks or datasets


```

---

## Contribution

Contributions are welcome! You can:

* Add new heuristic checks
* Extend support to more languages
* Improve dataset matching
* Add more test code samples

---

