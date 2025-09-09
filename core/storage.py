import threading
from datetime import datetime # MODIFIED: Import the datetime module

class FileStorage:
    """Handles buffering results in memory and writing to the output text file."""
    def __init__(self, collection_name=None):
        if not collection_name:
            sanitized_name = "default_scan"
            print("[STORAGE] WARNING: No name provided. Using 'default_scan' base name.")
        else:
            sanitized_name = collection_name.replace('.', '_').replace('-', '_')

        # --- MODIFIED: Add a timestamp to the filename ---
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_filename = f"{sanitized_name}_{timestamp}.txt"
        # --- End of modification ---

        self.lock = threading.Lock()
        self.results_buffer = [] 
        
        print(f"[STORAGE] Results will be saved to: '{self.output_filename}' after the scan.")

    def save_state(self, fingerprint, state_data):
        """Appends a discovered state to the in-memory buffer."""
        with self.lock:
            self.results_buffer.append((fingerprint, state_data))

    def flush_to_file(self):
        """Writes all buffered results to the file at once."""
        if not self.results_buffer:
            print("\n[STORAGE] No unique states were discovered, no report file will be generated.")
            return

        print(f"\n[STORAGE] Writing {len(self.results_buffer)} discovered states to {self.output_filename}...")
        
        # This formatting logic is now run only once at the end
        formatted_output = [f"Discovery results for target: {self.output_filename.replace('.txt', '')}\n{'='*60}\n\n"]
        
        for fingerprint, state_data in self.results_buffer:
            output_lines = []
            output_lines.append(f"--- New Unique State Found ---")
            output_lines.append(f"URL         : {state_data.get('url', 'N/A')}")
            output_lines.append(f"Fingerprint : {fingerprint}")
            output_lines.append(f"Timestamp   : {state_data.get('timestamp', 'N/A')}")
            
            tech_profile = state_data.get('technology_profile', [])
            if tech_profile:
                output_lines.append("\n[+] Technology Profile:")
                for tech in tech_profile:
                    output_lines.append(f"  - {tech}")

            output_lines.append("\n[+] Input Vectors:")
            vectors = state_data.get('attack_surface', {}).get('input_vectors', {})
            
            if not any(vectors.values()):
                 output_lines.append("  - None detected")
            
            if vectors.get('url_params'):
                output_lines.append("  URL Parameters:")
                for p in vectors['url_params']:
                    output_lines.append(f"    - Name: {p.get('name')}, Value: {p.get('value')}")
            
            if vectors.get('forms'):
                 output_lines.append("  Forms:")
                 for i, form in enumerate(vectors['forms'], 1):
                     output_lines.append(f"    - Form #{i}: Action='{form.get('action')}', Method='{form.get('method')}'")
                     for field in form.get('fields', []):
                         output_lines.append(f"      - Field: Name='{field.get('name')}', Type='{field.get('type')}'")

            output_lines.append("\n[+] Raw Request Template:")
            output_lines.append("```http")
            output_lines.append(f"{state_data.get('request_template', 'N/A')}")
            output_lines.append("```")
            
            formatted_output.append("\n".join(output_lines) + f"\n\n{'='*60}\n\n")

        try:
            with open(self.output_filename, 'w', encoding='utf-8') as f:
                f.write("".join(formatted_output))
            print("[STORAGE] Successfully saved all results.")
        except Exception as e:
            print(f"[STORAGE] Error writing to file '{self.output_filename}': {e}")