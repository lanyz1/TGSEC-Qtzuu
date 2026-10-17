// JavaScript Security Analyzer Frontend
// 
// NOTE: ALL ANALYSIS HAPPENS ON THE SERVER
// This frontend only:
// - Sends URLs to the server via API calls
// - Displays results received from the server
// - Handles UI interactions
//
// NO analysis, pattern matching, or file processing happens in the browser.

let currentResults = null;
let activeFilter = 'all';
let currentSessionId = null;
let allFilesData = [];

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
        btn.classList.add('active');
        document.getElementById(`${tab}-tab`).classList.remove('hidden');
    });
});

// Single URL analysis
document.getElementById('analyzeBtn').addEventListener('click', () => analyzeSingle());
document.getElementById('jsUrl').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') analyzeSingle();
});

// Multiple URLs analysis
document.getElementById('analyzeMultipleBtn').addEventListener('click', analyzeMultiple);

// File upload
document.getElementById('urlFile').addEventListener('change', handleFileSelect);
document.getElementById('analyzeFileBtn').addEventListener('click', analyzeFile);

// Back to files button
document.getElementById('backToFiles').addEventListener('click', () => {
    document.getElementById('results').classList.add('hidden');
    document.getElementById('files-section').classList.remove('hidden');
    document.getElementById('backToFiles').classList.add('hidden');
});

// Filter buttons
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeFilter = btn.dataset.filter;
        if (currentResults) {
            displayResults(currentResults);
        }
    });
});

function handleFileSelect(e) {
    const file = e.target.files[0];
    if (file) {
        document.getElementById('fileName').textContent = `Selected: ${file.name}`;
        document.getElementById('fileName').classList.remove('hidden');
        document.getElementById('analyzeFileBtn').disabled = false;
    }
}

async function analyzeSingle() {
    const url = document.getElementById('jsUrl').value.trim();
    
    if (!url) {
        showError('Please enter a JavaScript file URL');
        return;
    }
    
    // Validate URL
    try {
        new URL(url);
    } catch (e) {
        showError('Please enter a valid URL');
        return;
    }
    
    // Warn about 0.0.0.0
    let finalUrl = url;
    if (url.includes('0.0.0.0')) {
        if (!confirm('0.0.0.0 is not a valid address to connect to. Would you like to use localhost instead?')) {
            return;
        }
        finalUrl = url.replace('0.0.0.0', 'localhost');
        document.getElementById('jsUrl').value = finalUrl;
    }
    
    await analyzeUrls([finalUrl]);
}

async function analyzeMultiple() {
    const textarea = document.getElementById('multipleUrls');
    const urls = textarea.value.split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
    
    if (urls.length === 0) {
        showError('Please enter at least one URL');
        return;
    }
    
    // Fix 0.0.0.0 in URLs
    const fixedUrls = urls.map(url => url.includes('0.0.0.0') ? url.replace('0.0.0.0', 'localhost') : url);
    
    await analyzeUrls(fixedUrls);
}

async function analyzeFile() {
    const fileInput = document.getElementById('urlFile');
    const file = fileInput.files[0];
    
    if (!file) {
        showError('Please select a file');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    await analyzeUrls(null, formData);
}

async function analyzeUrls(urls, formData = null) {
    // Send analysis request to SERVER
    // All processing (file fetching, pattern matching, analysis) happens server-side
    const loading = document.getElementById('loading');
    const loadingText = document.getElementById('loading-text');
    const error = document.getElementById('error');
    const results = document.getElementById('results');
    const filesSection = document.getElementById('files-section');
    
    // Reset UI
    error.classList.add('hidden');
    results.classList.add('hidden');
    filesSection.classList.add('hidden');
    loading.classList.remove('hidden');
    
    try {
        let response;
        if (formData) {
            // File upload - server will process URLs and analyze files
            loadingText.textContent = 'Uploading and analyzing on server...';
            response = await fetch('/api/analyze', {
                method: 'POST',
                body: formData
            });
        } else {
            // Multiple URLs - server will fetch and analyze each file
            loadingText.textContent = `Server analyzing ${urls.length} file(s)...`;
            response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ urls })
            });
        }
        
        if (!response.ok) {
            const errorText = await response.text();
            let errorMsg = 'Analysis failed';
            try {
                const errorJson = JSON.parse(errorText);
                errorMsg = errorJson.error || errorMsg;
            } catch (e) {
                errorMsg = errorText || `Server error: ${response.status}`;
            }
            throw new Error(errorMsg);
        }
        
        const data = await response.json();
        
        if (!data || !data.results) {
            throw new Error('Invalid response from server');
        }
        
        currentSessionId = data.session_id;
        allFilesData = data.results;
        
        // If single file, show results directly
        if (data.results.length === 1) {
            currentResults = data.results[0];
            displayResults(currentResults);
            results.classList.remove('hidden');
        } else {
            // Multiple files - show file cards
            displayFileCards(data.results);
            filesSection.classList.remove('hidden');
        }
        
    } catch (err) {
        console.error('Analysis error:', err);
        showError(err.message || 'Failed to analyze JavaScript file(s)');
    } finally {
        loading.classList.add('hidden');
    }
}

function displayFileCards(files) {
    const grid = document.getElementById('files-grid');
    grid.innerHTML = '';
    
    files.forEach((file, index) => {
        const card = document.createElement('div');
        card.className = 'file-card';
        card.dataset.fileId = file.file_id;
        card.onclick = () => showFileResults(file);
        
        const totalFindings = (file.api_keys?.length || 0) + 
                             (file.credentials?.length || 0) + 
                             (file.emails?.length || 0) +
                             (file.xss_vulnerabilities?.length || 0) +
                             (file.xss_functions?.length || 0);
        
        const hasErrors = file.errors && file.errors.length > 0;
        
        card.innerHTML = `
            <div class="file-card-header">
                <div class="file-number">File ${file.file_id}</div>
                <div class="file-status ${hasErrors ? 'error' : 'completed'}">
                    ${hasErrors ? 'Error' : 'Completed'}
                </div>
            </div>
            <div class="file-url" title="${file.url}">${file.url}</div>
            <div class="file-stats">
                <div class="file-stat">
                    <i class="fas fa-key"></i>
                    <span>${file.api_keys?.length || 0} Keys</span>
                </div>
                <div class="file-stat">
                    <i class="fas fa-lock"></i>
                    <span>${file.credentials?.length || 0} Creds</span>
                </div>
                <div class="file-stat">
                    <i class="fas fa-exclamation-triangle"></i>
                    <span>${file.xss_vulnerabilities?.length || 0} XSS</span>
                </div>
                <div class="file-stat">
                    <i class="fas fa-code-branch"></i>
                    <span>${file.api_endpoints?.length || 0} Endpoints</span>
                </div>
            </div>
            ${hasErrors ? `<div style="margin-top: 10px; color: var(--danger); font-size: 0.85rem;">${file.errors[0]}</div>` : ''}
        `;
        
        grid.appendChild(card);
    });
}

function showFileResults(file) {
    currentResults = file;
    displayResults(file);
    
    // Update UI
    document.getElementById('files-section').classList.add('hidden');
    document.getElementById('results').classList.remove('hidden');
    document.getElementById('backToFiles').classList.remove('hidden');
    document.getElementById('results-title').textContent = `Analysis Results - File ${file.file_id}`;
    
    // Highlight active card
    document.querySelectorAll('.file-card').forEach(card => {
        card.classList.remove('active');
        if (card.dataset.fileId == file.file_id) {
            card.classList.add('active');
        }
    });
}

function showError(message) {
    const error = document.getElementById('error');
    error.textContent = message;
    error.classList.remove('hidden');
}

function displayResults(data) {
    const results = document.getElementById('results');
    results.classList.remove('hidden');
    
    // Update statistics
    updateStats(data);
    
    // Display findings
    displayFindings(data);
}

function updateStats(data) {
    document.getElementById('stat-api-keys').textContent = data.api_keys?.length || 0;
    document.getElementById('stat-credentials').textContent = data.credentials?.length || 0;
    document.getElementById('stat-emails').textContent = data.emails?.length || 0;
    document.getElementById('stat-xss').textContent = (data.xss_vulnerabilities?.length || 0) + (data.xss_functions?.length || 0);
    document.getElementById('stat-endpoints').textContent = data.api_endpoints?.length || 0;
}

function displayFindings(data) {
    const container = document.getElementById('findings-content');
    container.innerHTML = '';
    
    const sections = [
        { key: 'api_keys', title: 'API Keys', icon: 'fa-key', color: 'warning' },
        { key: 'credentials', title: 'Credentials', icon: 'fa-lock', color: 'danger' },
        { key: 'emails', title: 'Email Addresses', icon: 'fa-envelope', color: 'primary' },
        { key: 'xss_vulnerabilities', title: 'XSS Vulnerabilities', icon: 'fa-exclamation-triangle', color: 'danger' },
        { key: 'xss_functions', title: 'XSS Functions', icon: 'fa-code', color: 'danger' },
        { key: 'api_endpoints', title: 'API Endpoints', icon: 'fa-code-branch', color: 'success' },
        { key: 'parameters', title: 'Parameters', icon: 'fa-list', color: 'primary' },
        { key: 'paths_directories', title: 'Paths & Directories', icon: 'fa-folder', color: 'primary' },
        { key: 'interesting_comments', title: 'Interesting Comments', icon: 'fa-comment', color: 'warning' },
    ];
    
    sections.forEach(section => {
        const items = data[section.key] || [];
        const shouldShow = activeFilter === 'all' || activeFilter === section.key;
        
        if (!shouldShow) return;
        
        const sectionDiv = document.createElement('div');
        sectionDiv.className = `finding-section ${items.length === 0 ? 'empty' : ''}`;
        
        if (items.length > 0) {
            const title = document.createElement('h3');
            title.innerHTML = `<i class="fas ${section.icon}"></i> ${section.title} <span style="color: var(--text-muted); font-size: 0.9rem;">(${items.length})</span>`;
            sectionDiv.appendChild(title);
            
            items.forEach(item => {
                sectionDiv.appendChild(createFindingItem(item, section));
            });
        } else if (activeFilter === section.key) {
            const title = document.createElement('h3');
            title.innerHTML = `<i class="fas ${section.icon}"></i> ${section.title}`;
            sectionDiv.appendChild(title);
            const emptyMsg = document.createElement('div');
            emptyMsg.style.cssText = 'text-align: center; padding: 20px; color: var(--text-muted);';
            emptyMsg.textContent = 'No findings in this category';
            sectionDiv.appendChild(emptyMsg);
        }
        
        container.appendChild(sectionDiv);
    });
    
    if (container.children.length === 0) {
        container.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--text-muted);">No findings for this filter</div>';
    }
}

function createFindingItem(item, section) {
    const div = document.createElement('div');
    div.className = 'finding-item';
    
    const header = document.createElement('div');
    header.className = 'finding-header';
    
    const left = document.createElement('div');
    const type = document.createElement('div');
    type.className = 'finding-type';
    
    // For parameters, show more details
    if (section.key === 'parameters' && item.param_name) {
        type.innerHTML = `${item.type || section.title} <span style="color: var(--primary); font-weight: 600;">${escapeHtml(item.param_name)}</span>`;
    } else {
        type.textContent = item.type || section.title;
    }
    
    const line = document.createElement('div');
    line.className = 'finding-line';
    line.textContent = `Line ${item.line}`;
    
    left.appendChild(type);
    left.appendChild(line);
    
    const right = document.createElement('div');
    if (item.severity) {
        const severity = document.createElement('span');
        severity.className = `severity ${item.severity}`;
        severity.textContent = item.severity;
        right.appendChild(severity);
    }
    
    header.appendChild(left);
    header.appendChild(right);
    div.appendChild(header);
    
    // For parameters, show parameter name and value separately
    if (section.key === 'parameters') {
        if (item.param_name && item.param_value) {
            const paramInfo = document.createElement('div');
            paramInfo.className = 'finding-match';
            paramInfo.style.background = 'var(--bg-card)';
            paramInfo.style.padding = '10px';
            paramInfo.style.borderRadius = '6px';
            paramInfo.style.marginTop = '10px';
            paramInfo.innerHTML = `
                <div style="margin-bottom: 5px;"><strong>Parameter:</strong> <code style="color: var(--primary);">${escapeHtml(item.param_name)}</code></div>
                <div><strong>Value:</strong> <code style="color: var(--text-muted);">${escapeHtml(item.param_value)}</code></div>
            `;
            div.appendChild(paramInfo);
        }
    }
    
    // Match content
    if (item.match || item.parameter) {
        const match = document.createElement('div');
        match.className = 'finding-match';
        match.textContent = item.match || item.parameter || item.full_match;
        div.appendChild(match);
    }
    
    // Line content
    if (item.line_content) {
        const lineContent = document.createElement('div');
        lineContent.className = 'finding-match';
        lineContent.style.fontSize = '0.85rem';
        lineContent.style.marginTop = '10px';
        lineContent.textContent = item.line_content;
        div.appendChild(lineContent);
    }
    
    // Show code button - now available for parameters too
    if (item.context || item.line_content) {
        const showCodeBtn = document.createElement('button');
        showCodeBtn.className = 'show-code-btn';
        showCodeBtn.textContent = 'Show Code';
        showCodeBtn.onclick = () => toggleCode(showCodeBtn, item);
        div.appendChild(showCodeBtn);
        
        const codeContext = document.createElement('div');
        codeContext.className = 'code-context hidden';
        codeContext.id = `code-${item.line}-${Date.now()}`;
        codeContext.appendChild(createCodeBlock(item));
        div.appendChild(codeContext);
    }
    
    return div;
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function createCodeBlock(item) {
    const pre = document.createElement('pre');
    
    if (item.context) {
        const lines = item.context.split('\n');
        const startLine = item.context_start_line || (item.line - 2);
        
        lines.forEach((line, index) => {
            const lineNum = startLine + index;
            const codeLine = document.createElement('span');
            codeLine.className = `code-line ${lineNum === item.line ? 'highlight' : ''}`;
            
            const lineNumber = document.createElement('span');
            lineNumber.className = 'line-number';
            lineNumber.textContent = String(lineNum).padStart(4, ' ') + ': ';
            
            codeLine.appendChild(lineNumber);
            codeLine.appendChild(document.createTextNode(line || ' '));
            pre.appendChild(codeLine);
        });
    } else if (item.line_content) {
        // Fallback to line content if no context
        const codeLine = document.createElement('span');
        codeLine.className = 'code-line highlight';
        
        const lineNumber = document.createElement('span');
        lineNumber.className = 'line-number';
        lineNumber.textContent = String(item.line).padStart(4, ' ') + ': ';
        
        codeLine.appendChild(lineNumber);
        codeLine.appendChild(document.createTextNode(item.line_content));
        pre.appendChild(codeLine);
    }
    
    return pre;
}

function toggleCode(btn, item) {
    const codeContext = btn.nextElementSibling;
    if (codeContext.classList.contains('hidden')) {
        codeContext.classList.remove('hidden');
        btn.textContent = 'Hide Code';
    } else {
        codeContext.classList.add('hidden');
        btn.textContent = 'Show Code';
    }
}
