#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os
import json
from datetime import datetime
import yaml
from dotenv import dotenv_values
import time
import shlex


# Constants
CLI_BIN_LOC = "/home/modeluser/BitNet/build/bin/llama-cli"
MODEL_LOC = "/home/modeluser/BitNet/models/BitNet-b1.58-2B-4T/ggml-model-i2_s.gguf"
#SYSTEM_PROMPT = "You are a helpful AI assistant integrated into a DevSecOps platform. Provide concise, technical responses."
SYSTEM_PROMPT = "One of your function is to receive a security artifact (such as CVE data, configuration files, or vulnerability reports) and provide a concise, technical summary based on the user's query/promp. All necessary context will be provided in each prompt. Do not add conversational filler."


# for tracking the last run's info
LAST_RUN_INFO_FILE = '/tmp/chat_last_run.json'
SESSION_STATE_FILE = '/tmp/chat_session_state.json'


LOG_FILE = "chat_log.txt"
TEMP_OUTPUT = "chat_temp.txt"
SESSION_TRACKER_FILE = '/tmp/chat_session.cfg'
MAX_FILE_SIZE = 5000  # Approx. 1200 tokens, safe for a 2k context window
MAPPING_SAMPLE_BUDGET = 2500 # Max total characters for all samples in Pass 1
CHUNK_TARGET_SIZE = 3500 # Target size for each chunk 1k token
PASS_2_ANALYSIS_OUTPUT = "/tmp/chat_pass2_analysis.txt" # store the combined findings from this pass.

PASS_1_MAP_OUTPUT = "/tmp/chat_pass1_map.json" # Output file for Pass 1 mapping

# LLM execution defaults
retries = 3
timeout = 300 # time out changed fro 120 to 300 second -> 5 minutes
show_thinking_indicator = True


#######################################
# Helper and llm functions
#######################################

def save_last_run_info(args):
    """Saves non-setting information from the current run, like the last prompt."""
    try:
        info = {'last_prompt': args.prompt}
        with open(LAST_RUN_INFO_FILE, 'w', encoding='utf-8') as f:
            json.dump(info, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save last run info: {e}", file=sys.stderr)

def load_last_run_info():
    """Loads key information from the last run's file."""
    if not os.path.exists(LAST_RUN_INFO_FILE):
        return {}
    try:
        with open(LAST_RUN_INFO_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: Could not read last run info file: {e}", file=sys.stderr)
        return {}

def generate_chunk_manifest(file_paths, chunk_target_size=CHUNK_TARGET_SIZE):
    """
    Implements the "Card Catalog" generator.
    Scans files to create a manifest of chunk locations (byte offsets)
    without loading the file contents into memory.
    """
    manifest = []
    chunk_id_counter = 0
    for file_path in file_paths:
        if not os.path.exists(file_path):
            continue
        try:
            # Open with 'rb' to accurately tell byte positions
            with open(file_path, 'rb') as f:
                # Read the whole content once for splitting, but decode for processing.
                # This is a pragmatic choice; it avoids complex byte-stream parsing
                # and solves the primary problem: storing all chunks in memory.
                content = f.read().decode('utf-8', errors='ignore')
                paragraphs = content.split('\n\n')
                current_chunk_str = ""
                chunk_start_byte = 0

                for paragraph in paragraphs:
                    if not paragraph.strip():
                        # Even empty paragraphs consume bytes (newlines)
                        chunk_start_byte += len(paragraph.encode('utf-8', errors='ignore')) + 2 # for '\n\n'
                        continue

                    # If adding the next paragraph makes the chunk too big, finalize the current one
                    if len(current_chunk_str) + len(paragraph) > chunk_target_size and current_chunk_str:
                        chunk_byte_len = len(current_chunk_str.encode('utf-8', errors='ignore'))
                        manifest.append({
                            "id": chunk_id_counter,
                            "file_path": file_path,
                            "start_byte": chunk_start_byte,
                            "end_byte": chunk_start_byte + chunk_byte_len
                        })
                        chunk_id_counter += 1
                        chunk_start_byte += chunk_byte_len
                        current_chunk_str = ""

                    current_chunk_str += paragraph + "\n\n"

                # Add the last remaining chunk
                if current_chunk_str:
                    chunk_byte_len = len(current_chunk_str.encode('utf-8', errors='ignore'))
                    manifest.append({
                        "id": chunk_id_counter,
                        "file_path": file_path,
                        "start_byte": chunk_start_byte,
                        "end_byte": chunk_start_byte + chunk_byte_len
                    })
                    chunk_id_counter += 1
            return manifest
        except Exception as e:
            print(f"Warning: Could not create chunk manifest for file {file_path}: {e}", file=sys.stderr)
            return []

def read_chunks_from_manifest(manifest, selected_ids):
    """
    Performs targeted reading of chunks from the original files using the manifest.
    This is the "just-in-time" content loading part of the "Card Catalog" architecture.
    """
    chunk_contents = {}
    # Create a quick lookup map for the selected IDs
    id_to_chunk_meta = {chunk['id']: chunk for chunk in manifest if chunk['id'] in selected_ids}

    for chunk_id in selected_ids:
        if chunk_id in id_to_chunk_meta:
            meta = id_to_chunk_meta[chunk_id]
            try:
                with open(meta['file_path'], 'rb') as f:
                    f.seek(meta['start_byte'])
                    content_bytes = f.read(meta['end_byte'] - meta['start_byte'])
                    chunk_contents[chunk_id] = content_bytes.decode('utf-8', errors='ignore')
            except Exception as e:
                print(f"Warning: Could not read chunk id {chunk_id} from {meta['file_path']}: {e}", file=sys.stderr)
    return chunk_contents

def run_non_interactive_analysis(args, settings):
    """
    Orchestrates the multi-pass analysis for non-interactive mode.
    Handles both small files (single-pass) and large files (multi-pass).
    """
    save_last_run_info(args)
    cleanup_temp_files()

    total_size = 0
    final_answer = ""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if args.file:
        for path in args.file:
            if os.path.exists(path):
                total_size += os.path.getsize(path)

    if total_size <= MAX_FILE_SIZE:
        print("File size is within the single-pass limit. Performing direct analysis...")
        full_file_content = ""
        if args.file:
            for path in args.file:
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        full_file_content += f"\n\n--- START OF FILE: {os.path.basename(path)} ---\n"
                        full_file_content += f.read()
                        full_file_content += f"\n--- END OF FILE: {os.path.basename(path)} ---\n"
        user_prompt = args.prompt + full_file_content
        formatted_prompt = format_prompt(settings['system_prompt'], user_prompt)
        print("[Pass 1/1] Generating final analysis...")
        output = call_llm(
            prompt=formatted_prompt, cli_bin_loc=settings['cli_bin_loc'], model_loc=settings['model_loc'],
            max_tokens=settings.get('tokens'), show_thinking=show_thinking_indicator,
            temperature=settings.get('temperature'), top_p=settings.get('top_p'),
            repeat_penalty=settings.get('repeat_penalty'), ctx_size=settings.get('ctx_size'),
            seed=settings.get('seed'), threads=settings.get('threads')
        )
        save_to_log(output, args.prompt, timestamp)
        final_answer = extract_response()
        print("\n--- Final Answer ---")
        if args.full_verbose: print(output)
        else: print(final_answer)

    else:
        print(f"Total file size ({total_size / 1024:.1f} KB) exceeds limit. Starting multi-pass analysis.")
        
        print("\n[Pass 1/3] Mapping document structure (one by one)...")
        final_map = {}
        if args.file:
            for path in args.file:
                if not os.path.exists(path): continue
                print(f"  - Mapping {os.path.basename(path)}...")
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    sample_content = f.read(MAPPING_SAMPLE_BUDGET)
                map_prompt_content = ("Analyze the beginning of the following document and create a structural map. "
                                      "Provide a one-sentence summary and a list of key topics or sections. "
                                      "Respond ONLY with a single, minified JSON object containing 'summary' and 'topics' keys.\n\n"
                                      f"--- DOCUMENT SAMPLE ---\n{sample_content}")
                mapping_prompt = format_prompt(settings['system_prompt'], map_prompt_content)
                map_output_raw = call_llm(
                    prompt=mapping_prompt, cli_bin_loc=settings['cli_bin_loc'], model_loc=settings['model_loc'],
                    max_tokens=1024, show_thinking=False, temperature=0.2,
                    ctx_size=settings.get('ctx_size')
                )
                log_prompt_desc = f"[PASS 1 - MAPPING on {os.path.basename(path)}] User Query: {args.prompt}"
                save_to_log(map_output_raw, log_prompt_desc, timestamp)
                
                map_json_str = extract_response()
                try:
                    final_map[os.path.basename(path)] = json.loads(map_json_str)
                except json.JSONDecodeError:
                    print(f"    Warning: Could not parse map for {os.path.basename(path)}. Skipping.")
        try:
            with open(PASS_1_MAP_OUTPUT, 'w', encoding='utf-8') as f:
                json.dump(final_map, f, indent=2)
            print(f"Successfully created and saved complete document map to {PASS_1_MAP_OUTPUT}")
            parsed_map = final_map
        except Exception as e:
            print(f"\n[Error] Could not save the final document map: {e}"); sys.exit(1)
        
        # --- NEW: Check if the map is empty and exit if it is ---
        if not parsed_map:
            print("\n[Error] Failed to create a document map in Pass 1. Cannot continue. Try again.")
            sys.exit(1)

        print("\n[Pass 2/3] Analyzing relevant document sections...")

        print("  - Generating chunk manifest (Card Catalog)...")
        chunk_manifest = generate_chunk_manifest(args.file)
        if not chunk_manifest: print("Could not generate a chunk manifest. Aborting."); sys.exit(1)
        print(f"  - Found {len(chunk_manifest)} total chunks across all files.")

        # ### --- NEW: Smart Selection Logic --- ###
        selected_indices = []
        map_text = json.dumps(parsed_map).lower()
        
        # Define keywords that suggest the map is already highly relevant
        # This list can be expanded over time.
        #solve the issue of LLM's inability to solve complex problems 
        relevance_keywords = [
            # General Security
            'vulnerability', 'security', 'overflow', 'exploit', 'password', 'credential', 'secret',
            
            # CVE & Issue Types
            'cve', 'rce', 'remote code execution', 'xss', 'cross-site scripting', 'sqli',
            'sql injection', 'privilege escalation', 'arbitrary code', 'denial of service',
            'dos', 'malicious', 'advisory', 'threat', 'attack vector', 'unauthorized access',

            # Mitigation & Solutions
            'patch', 'mitigation', 'mitigate', 'remediate', 'remediation', 'workaround',
            'update', 'upgrade', 'harden', 'hardening', 'sanitize input', 'disable', 'solution',
            'cvss', 'severity', 'critical', 'high risk',
            'buffer', 'strcpy', 'memcpy', 'deserialization',
            'injection', 'traversal', 'bypass', 'backdoor',
            'fix', 'hotfix', 'vendor', 'advisory', 'disclosure'        
            ]
        
        # If the map text contains relevant keywords, just select all chunks from that file.
        if any(keyword in map_text for keyword in relevance_keywords):
            print("  - [Smart Select] Map contains relevant keywords. Selecting all chunks for analysis.")
            selected_indices = [chunk['id'] for chunk in chunk_manifest]
        # ### --- END of Smart Selection Logic --- ###

        # If the smart select didn't trigger, then proceed with the LLM selection as before.
        if not selected_indices:
            print("  - Asking LLM to select relevant chunks...")
            map_str = json.dumps(parsed_map, indent=2)
            lightweight_chunk_info = json.dumps([{"id": chunk["id"], "file": os.path.basename(chunk["file_path"])} for chunk in chunk_manifest])
            
            selection_prompt = (f"User Query: '{args.prompt}'\n\n"
                                f"Document Map:\n{map_str}\n\n"
                                f"Available Chunks:\n{lightweight_chunk_info}\n\n"
                                "Based on the user query and the map, which chunk 'id's are most likely to contain the answer? "
                                "Be selective to stay focused. Respond ONLY with a single, minified JSON list of integer ids.")
            selection_formatted_prompt = format_prompt(settings['system_prompt'], selection_prompt)
            selected_chunks_raw = call_llm(
                prompt=selection_formatted_prompt, cli_bin_loc=settings['cli_bin_loc'], model_loc=settings['model_loc'],
                max_tokens=512, show_thinking=show_thinking_indicator, temperature=0.1,
                ctx_size=settings.get('ctx_size')
            )
            save_to_log(selected_chunks_raw, f"[PASS 2 - SELECTION] User Query: {args.prompt}", timestamp)
            
            try:
                selected_indices = json.loads(extract_response())
                if not isinstance(selected_indices, list): raise ValueError("Not a list")
            except (json.JSONDecodeError, ValueError) as e:
                print(f"\n[Error] Could not parse the list of selected chunks from the LLM: {e}"); print("Raw output:", extract_response()); sys.exit(1)
        
        print(f"LLM selected {len(selected_indices)} relevant chunks: {selected_indices}")
        if not selected_indices: print("The LLM determined that no specific chunks are relevant to the query. Cannot proceed."); sys.exit(0)

        print("  - Performing targeted read of selected chunk contents...")
        selected_chunk_contents = read_chunks_from_manifest(chunk_manifest, selected_indices)

        ANALYSIS_BATCH_CHAR_BUDGET = 4000
        current_batch_content = ""
        open(PASS_2_ANALYSIS_OUTPUT, 'w').close()
        
        for chunk_id in selected_indices:
            if chunk_id not in selected_chunk_contents:
                print(f"Warning: LLM selected chunk id {chunk_id}, which could not be read. Skipping.")
                continue

            chunk_content = selected_chunk_contents[chunk_id]
            if len(current_batch_content) + len(chunk_content) > ANALYSIS_BATCH_CHAR_BUDGET:
                if current_batch_content:
                    analysis_prompt = (f"User Query: '{args.prompt}'\n\n"
                                       "Extract all information, facts, and findings relevant to the user query from the following text. Be detailed and quote important parts.\n\n--- TEXT ---\n"
                                       f"{current_batch_content}")
                    analysis_formatted_prompt = format_prompt(settings['system_prompt'], analysis_prompt)
                    findings_raw = call_llm(prompt=analysis_formatted_prompt, cli_bin_loc=settings['cli_bin_loc'], model_loc=settings['model_loc'], max_tokens=1024, ctx_size=settings.get('ctx_size'))
                    save_to_log(findings_raw, f"[PASS 2 - ANALYSIS BATCH] User Query: {args.prompt}", timestamp)
                    findings = extract_response()
                    with open(PASS_2_ANALYSIS_OUTPUT, 'a', encoding='utf-8') as f: f.write(findings + "\n\n")
                current_batch_content = chunk_content
            else:
                current_batch_content += chunk_content + "\n\n"

        if current_batch_content:
            analysis_prompt = (f"User Query: '{args.prompt}'\n\n"
                               "Extract all information, facts, and findings relevant to the user query from the following text. Be detailed and quote important parts.\n\n--- TEXT ---\n"
                               f"{current_batch_content}")
            analysis_formatted_prompt = format_prompt(settings['system_prompt'], analysis_prompt)
            findings_raw = call_llm(prompt=analysis_formatted_prompt, cli_bin_loc=settings['cli_bin_loc'], model_loc=settings['model_loc'], max_tokens=1024, ctx_size=settings.get('ctx_size'))
            save_to_log(findings_raw, f"[PASS 2 - ANALYSIS FINAL BATCH] User Query: {args.prompt}", timestamp)
            findings = extract_response()
            with open(PASS_2_ANALYSIS_OUTPUT, 'a', encoding='utf-8') as f: f.write(findings + "\n\n")

        print(f"Analysis of relevant chunks complete. Findings saved to {PASS_2_ANALYSIS_OUTPUT}")
        
        print("\n[Pass 3/3] Synthesizing final answer...")
        try:
            with open(PASS_2_ANALYSIS_OUTPUT, 'r', encoding='utf-8') as f: findings_text = f.read()
        except FileNotFoundError: print("\n[Error] Findings file not found. Cannot synthesize."); sys.exit(1)
        if not findings_text.strip(): print("\nNo findings were extracted in the analysis phase. Cannot provide a final answer."); sys.exit(0)
        if len(findings_text) > ANALYSIS_BATCH_CHAR_BUDGET:
            print(f"Warning: Collected findings are very large. Truncating for final synthesis.")
            findings_text = findings_text[:ANALYSIS_BATCH_CHAR_BUDGET]
        synthesis_prompt_content = (f"Your task is to answer the user's original query based on the provided research notes. Do not just list the notes; synthesize them into a single, coherent, well-structured final answer.\n\n"
                                    f"USER'S ORIGINAL QUERY: '{args.prompt}'\n\n"
                                    f"--- RESEARCH NOTES AND FINDINGS ---\n"
                                    f"{findings_text}")
        synthesis_prompt = format_prompt(settings['system_prompt'], synthesis_prompt_content)
        final_output_raw = call_llm(
            prompt=synthesis_prompt, cli_bin_loc=settings['cli_bin_loc'], model_loc=settings['model_loc'],
            max_tokens=settings.get('tokens'), show_thinking=show_thinking_indicator, temperature=0.7,
            top_p=settings.get('top_p'), repeat_penalty=settings.get('repeat_penalty'),
            ctx_size=settings.get('ctx_size'), seed=settings.get('seed'), threads=settings.get('threads')
        )
        save_to_log(final_output_raw, f"[PASS 3 - SYNTHESIS] User Query: {args.prompt}", timestamp)
        final_answer = extract_response()
        print("\n--- Final Answer ---")
        if args.full_verbose: print(final_output_raw)
        else: print(final_answer)

    if args.show_work:
        print("\n\n--- Intermediate Work ---")
        if total_size > MAX_FILE_SIZE:
            map_exists = os.path.exists(PASS_1_MAP_OUTPUT)
            findings_exist = os.path.exists(PASS_2_ANALYSIS_OUTPUT)

            if not map_exists and not findings_exist:
                print("Multi-pass strategy was used, but no intermediate files were found (an error may have occurred).")
            
            if map_exists:
                print(f"\n--- Document Map (from {PASS_1_MAP_OUTPUT}) ---")
                with open(PASS_1_MAP_OUTPUT, 'r', encoding='utf-8') as f:
                    print(f.read())
            
            if findings_exist:
                print(f"\n--- Raw Findings (from {PASS_2_ANALYSIS_OUTPUT}) ---")
                with open(PASS_2_ANALYSIS_OUTPUT, 'r', encoding='utf-8') as f:
                    print(f.read())
        else:
            print("(--show-work is active, but no intermediate files were generated because the input was handled by the more efficient single-pass strategy.)")



def cleanup_temp_files():
    """Deletes temporary pass files to ensure a clean run."""
    files_to_delete = [PASS_1_MAP_OUTPUT, PASS_2_ANALYSIS_OUTPUT]
    for f in files_to_delete:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError as e:
                print(f"Warning: Could not delete temp file {f}: {e}", file=sys.stderr)

def save_to_log(output, prompt, timestamp):
    """Save output to log file with timestamp and prompt"""
    with open(LOG_FILE, 'a') as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write(f"Prompt: {prompt}\n")
        f.write(f"{'='*60}\n")
        f.write(output)
        f.write(f"\n{'='*60}\n\n")

def load_configuration(file_path):
    config = {}
    try:
        if file_path.endswith(('.yaml', '.yml')):
            with open(file_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
        elif file_path.endswith('.env'):
            config = dotenv_values(file_path)
        if config:
            return {str(k).lower(): v for k, v in config.items()}
        return {}
    except FileNotFoundError:
        print(f"Warning: Configuration file not found at '{file_path}'", file=sys.stderr)
        return {}
    except Exception as e:
        print(f"Warning: Error parsing configuration file '{file_path}': {e}", file=sys.stderr)
        return {}

def get_session_config_path():
    try:
        if not os.path.exists(SESSION_TRACKER_FILE):
            return None
        with open(SESSION_TRACKER_FILE, 'r', encoding='utf-8') as f:
            path = f.read().strip()
            return path if path else None
    except Exception as e:
        print(f"Warning: Could not read session tracker file: {e}", file=sys.stderr)
        return None

def save_session_config_path(path):
    if not os.path.isfile(path):
        print(f"Error: Configuration file not found at '{path}'", file=sys.stderr)
        return False
    try:
        with open(SESSION_TRACKER_FILE, 'w', encoding='utf-8') as f:
            f.write(path)
        return True
    except Exception as e:
        print(f"Error: Could not write to session tracker file: {e}", file=sys.stderr)
        return False

def reset_session_state():
    """Resets the entire session by deleting all temporary, config, and history files."""
    files_to_reset = [
        SESSION_TRACKER_FILE,
        LAST_RUN_INFO_FILE,
        PASS_1_MAP_OUTPUT,
        PASS_2_ANALYSIS_OUTPUT,
        SESSION_STATE_FILE  # Add the new state file to the reset list
    ]
    print("Resetting session state...")
    for f in files_to_reset:
        if os.path.exists(f):
            try:
                os.remove(f)
                print(f" - Removed {f}")
            except OSError as e:
                print(f"Warning: Could not remove session file {f}: {e}", file=sys.stderr)
    print("\nSession state has been reset to defaults.")

def load_session_state():
    """Loads the persistent session state from its JSON file."""
    if not os.path.exists(SESSION_STATE_FILE):
        return {}
    try:
        with open(SESSION_STATE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: Could not read session state file: {e}", file=sys.stderr)
        return {}
def save_session_state(settings):
    """Saves the mutable settings to the session state file."""
    # Define which keys are part of the mutable session
    mutable_keys = [
        'system_prompt', 'tokens', 'temperature', 'top_p', 'repeat_penalty',
        'ctx_size', 'seed', 'threads'
    ]
    
    state_to_save = {key: settings.get(key) for key in mutable_keys}
    
    try:
        with open(SESSION_STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(state_to_save, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save session state: {e}", file=sys.stderr)

#######################################
# File Utilities
#######################################

def validate_environment_and_inputs(file_paths=None):
    if not os.path.isfile(CLI_BIN_LOC):
        print(f"[Error] LLM CLI not found at {CLI_BIN_LOC}")
        sys.exit(1)
    if not os.path.isfile(MODEL_LOC):
        print(f"[Error] Model file not found at {MODEL_LOC}")
        sys.exit(1)
    if file_paths:
        for path in file_paths:
            if not os.path.isfile(path):
                print(f"[Warning] File '{path}' not found. Skipping.")

def read_file_in_chunks(file_path, chunk_size=MAX_FILE_SIZE):
    if not os.path.exists(file_path):
        print(f"[Warning] File '{file_path}' not found.")
        return
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            yield data

def view_file(file_path):
    if not os.path.exists(file_path):
        print(f"[Warning] File '{file_path}' not found.")
        return
    size_kb = os.path.getsize(file_path) / 1024
    chunks = list(read_file_in_chunks(file_path))
    if not chunks:
        return
    print(f"File Size: {size_kb:.0f} KB")
    print(f"--- {file_path} ---")
    for i, chunk in enumerate(chunks, start=1):
        print(chunk.strip())
        if i == len(chunks):
            print(f"--- End ---\n")

def clear_file(file_path):
    try:
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            print(f"The file '{file_path}' is already empty or does not exist.")
            return
        confirm = input(f"Are you sure you want to clear '{file_path}'? [y/N]: ")
        if confirm.lower() == 'y':
            open(file_path, 'w').close()
            print(f"Successfully cleared '{file_path}'.")
        else:
            print("Operation cancelled.")
    except Exception as e:
        print(f"Error clearing file: {e}")

def view_file_contents(file_paths):
    image_exts = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.webp'}
    for path in file_paths:
        ext = os.path.splitext(path)[1].lower()
        if ext in image_exts:
            print(f"Skipping '{path}' (I don't open image files).")
            continue
        view_file(path)

#######################################
# LLM Utilities
#######################################

def format_prompt(system_prompt, user_prompt):
    return f"""<|start_header_id|>system<|end_header_id|>
{system_prompt}<|eot_id|>
<|start_header_id|>user<|end_header_id|>
{user_prompt}<|eot_id|>
<|start_header_id|>assistant<|end_header_id|>
"""

def call_llm(prompt, cli_bin_loc, model_loc, max_tokens=512, show_thinking=True, temperature=0.8, top_p=0.9, repeat_penalty=1.0, ctx_size=2048, seed=None, threads=None):
    if show_thinking:
        print("\nThinking...", end='', flush=True)
    cmd = [
        cli_bin_loc,
        "-m", model_loc,
        "-p", prompt,
        "--n-predict", str(max_tokens),
        "--temp", str(temperature),
        "--top-p", str(top_p),
        "--repeat-penalty", str(repeat_penalty),
        "-c", str(ctx_size)
    ]
    if seed is not None: cmd.extend(["--seed", str(seed)])
    if threads is not None: cmd.extend(["--threads", str(threads)])


    # --- ADD THIS FOR DEBUGGING ---
    #print(f"\n[DEBUG] Running command: {' '.join(shlex.quote(str(c)) for c in cmd)}\n")
    # ------

    for attempt in range(1, retries + 1):
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=timeout
            )
            if show_thinking:
                print("\r" + " " * 20 + "\r", end='', flush=True)

            if result.returncode != 0:
                print(f"[Error] llama-cli exited with code {result.returncode}. Retrying ({attempt}/{retries})...")
                time.sleep(1)
                continue

            output = result.stdout
            with open(TEMP_OUTPUT, 'w', encoding='utf-8') as f:
                f.write(output)
            return output

        except subprocess.TimeoutExpired:
            print(f"[Warning] llama-cli timed out (attempt {attempt}/{retries}). Retrying...")
        except Exception as e:
            print(f"[Error] Unexpected exception: {e}")
            time.sleep(1)

    print(f"[Error] Failed after {retries} attempts.")
    sys.exit(1)


def extract_response():
    try:
        with open(TEMP_OUTPUT, 'r', encoding='utf-8') as f:
            output = f.read()
    except FileNotFoundError:
        return f"[Error: '{TEMP_OUTPUT}' not found.]"

    start_marker = '<|start_header_id|>assistant<|end_header_id|>'
    try:
        start_pos = output.rindex(start_marker) + len(start_marker)
        response_block = output[start_pos:]
    except ValueError:
        start_marker_alt = '\nassistant\n'
        try:
            start_pos = output.rindex(start_marker_alt) + len(start_marker_alt)
            response_block = output[start_pos:]
        except ValueError:
            return "[No response extracted - 'assistant' marker missing.]"

    end_marker = '[end of text]'
    end_pos = response_block.find(end_marker)
    clean_response = response_block[:end_pos].strip() if end_pos != -1 else response_block.strip()

    # Robustly find a JSON object OR a JSON list
    json_obj_start = clean_response.find('{')
    json_obj_end = clean_response.rfind('}')
    json_list_start = clean_response.find('[')
    json_list_end = clean_response.rfind(']')

    if json_obj_start != -1 and json_obj_end != -1:
        # It's an object
        return clean_response[json_obj_start : json_obj_end + 1]
    elif json_list_start != -1 and json_list_end != -1:
        # It's a list
        return clean_response[json_list_start : json_list_end + 1]

    return clean_response


#######################################
# Main
#######################################

def main():
    parser = argparse.ArgumentParser(
        description='Engage in an interactive, conversational dialogue with a locally-hosted (LLM) that has been specifically optimized for the purpose of conducting in-depth cybersecurity analysis.',
        prog='chat',
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Argument groups (no changes here)
    prompt_group = parser.add_argument_group('------------------------Prompting Arguments------------------------')
    gen_group = parser.add_argument_group('------------------------Generation Arguments------------------------')
    log_group = parser.add_argument_group('------------------------Log Management Arguments------------------------')
    perf_group = parser.add_argument_group('------------------------Performance Arguments------------------------')

    # Argument definitions (no changes here)
    prompt_group.add_argument('-p', '--prompt', metavar='TEXT', help='The prompt/question to send to the LLM.')
    prompt_group.add_argument('-f', '--file', nargs='+', metavar='FILE_PATH', help='Files to read and include in prompt.')
    parser.add_argument('--view-log', action='store_true', help='View the chat log file of the session')
    parser.add_argument('--clear-log', action='store_true', help='Clear the chat log file of the session')
    parser.add_argument('--view-temp', action='store_true', help='View the latest LLM output file of the session')
    parser.add_argument('--clear-temp', action='store_true', help='Clear the latest LLM output file of the session')
    gen_group.add_argument('--config', metavar='FILE_PATH', help='Load settings from a specified config file, starting a new session.')
    gen_group.add_argument('--reset-config', action='store_true', help='Reset session configuration.')
    gen_group.add_argument('--view-config', action='store_true', help='Display active configuration.')
    gen_group.add_argument('--system', dest='system_prompt', help='Override default system prompt.')
    gen_group.add_argument('--tokens', type=int, help='Maximum number of tokens to generate.')
    gen_group.add_argument('--temperature', type=float, help='Randomness of output.')
    gen_group.add_argument('--top-p', type=float, help='Top-p sampling.')
    gen_group.add_argument('--repeat-penalty', type=float, help='Repeat penalty.')
    gen_group.add_argument('-s', '--seed', type=int, help='Random seed for reproducibility.')
    perf_group.add_argument('--ctx-size', type=int, help='Prompt context window size.')
    perf_group.add_argument('--threads', type=int, help='Number of CPU threads.')
    perf_group.add_argument('--full-verbose', action='store_true', help='Show full LLM output.')
    perf_group.add_argument('--show-work', action='store_true', help='Display the intermediate map and findings after the final answer.')

    args = parser.parse_args()

    # --- Configuration Loading (NEW DYNAMIC LOGIC) ---
    if args.reset_config:
        reset_session_state()
        sys.exit(0)

    def load_and_normalize_config(path):
        config = load_configuration(path) or {}
        if 'max_tokens' in config: config['tokens'] = config.pop('max_tokens')
        if 'default_prompt' in config: config['default_prompt'] = config.pop('default_prompt')
        return config

    # 1. Start with hardcoded defaults
    settings = {
        'cli_bin_loc': CLI_BIN_LOC, 'model_loc': MODEL_LOC, 'system_prompt': SYSTEM_PROMPT,
        'tokens': 512, 'temperature': 0.8, 'top_p': 0.9, 'repeat_penalty': 1.0,
        'seed': None, 'ctx_size': 2048, 'threads': None
    }
    
    # 2. Load the persistent session state, which overrides defaults
    session_state = load_session_state()
    if session_state:
        settings.update(session_state)
    else:
        # If no session state, try to initialize from the tracked config file
        session_config_path = get_session_config_path()
        if session_config_path:
            settings.update(load_and_normalize_config(session_config_path))

    # 3. If a new config file is specified, it resets the session to its contents
    if args.config and save_session_config_path(args.config):
        print(f"[Config Notice] Starting new session with settings from {os.path.basename(args.config)}")
        settings.update(load_and_normalize_config(args.config))

    # 4. Apply CLI arguments as the final override for this run
    cli_args = {key: value for key, value in vars(args).items() if value is not None}
    settings.update(cli_args)

    # 5. SAVE the updated state back to the session file, making overrides permanent
    save_session_state(settings)

    # --- Standalone Command Handling ---
    if args.view_log: view_file(LOG_FILE); sys.exit(0)
    if args.clear_log: clear_file(LOG_FILE); sys.exit(0)
    if args.view_temp: view_file(TEMP_OUTPUT); sys.exit(0)
    if args.clear_temp: clear_file(TEMP_OUTPUT); sys.exit(0)
    
    # --- Main Execution Logic ---
    if args.prompt or args.file:
        if not args.prompt and settings.get('default_prompt'):
            args.prompt = settings.get('default_prompt')
            print(f"[Config Notice] Using default prompt from configuration: \"{args.prompt}\"")
        if not args.prompt:
            print("\n[Error] An input file was provided, but no prompt was specified.", file=sys.stderr)
            sys.exit(1)
        validate_environment_and_inputs(args.file)
        run_non_interactive_analysis(args, settings)

    elif args.config or args.view_config:
        title = "--- Active Session Settings ---"
        if args.config: title = f"--- Session Settings Loaded from {os.path.basename(args.config)} ---"
        print(title)
        
        flags_to_hide = {'view_config', 'view_log', 'view_temp', 'clear_log', 'clear_temp',
                         'reset_config', 'show_work', 'full_verbose', 'config', 'prompt', 'file'}
        display_settings = {k: v for k, v in settings.items() if k not in flags_to_hide}
        last_run_info = load_last_run_info()
        display_settings['last_prompt'] = last_run_info.get('last_prompt', None)
        
        if display_settings:
            max_key_length = max(len(k) for k in display_settings.keys())
            for k, v in sorted(display_settings.items()):
                if isinstance(v, str) and '\n' in v:
                    print(f"{k:<{max_key_length}} : ---")
                    for line in v.split('\n'): print(f"  {line}")
                    print("  ---")
                else:
                    print(f"{k:<{max_key_length}} : {v}")
        print("-----------------------------------")
        sys.exit(0)

    else:
        parser.print_help()
        sys.exit(0)
if __name__ == "__main__":
    main()