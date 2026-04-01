document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const form = document.getElementById('upload-form');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const resetBtn = document.getElementById('reset-btn');
    const uploadView = document.getElementById('upload-view');

    // Drag and drop event listeners
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
    });

    dropZone.addEventListener('drop', handleDrop, false);
    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', function() {
        if (this.files.length) handleFiles(this.files);
    });

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        handleFiles(files);
    }

    function handleFiles(files) {
        const file = files[0];
        if (!file.name.endsWith('.eml')) {
            alert('Please upload a .eml file');
            return;
        }

        // Show loading state
        form.classList.add('hidden');
        loading.classList.remove('hidden');

        const formData = new FormData();
        formData.append('file', file);

        fetch('/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                loading.classList.add('hidden');
                alert('Error: ' + data.error);
                form.classList.remove('hidden');
            } else {
                uploadView.classList.add('hidden'); // Hide entire upload panel
                renderResults(data);
                resetBtn.classList.remove('hidden');
            }
        })
        .catch(error => {
            loading.classList.add('hidden');
            alert('An error occurred during upload/analysis.');
            form.classList.remove('hidden');
            console.error(error);
        });
    }

    function renderResults(data) {
        // Render Score
        const risk = data.risk_assessment;
        document.getElementById('score-value').innerText = risk.score;
        
        // Render Progress Ring (SVG)
        const circle = document.getElementById('score-circle');
        const percentage = (risk.score / risk.max_score) * 100;
        circle.setAttribute('stroke-dasharray', `${percentage}, 100`);
        
        // Render Risk Badge
        const badge = document.getElementById('risk-level-badge');
        badge.innerText = `LEVEL: ${risk.risk_level.toUpperCase()}`;
        badge.className = `risk-text badge-${risk.risk_level.toLowerCase()}`;
        
        // Color the circle based on risk
        circle.style.stroke = `var(--${risk.risk_level.toLowerCase()})`;

        // Render Headers and Findings
        const headersList = document.getElementById('headers-list');
        headersList.innerHTML = '';
        
        if (risk.findings && risk.findings.length > 0) {
            risk.findings.forEach(finding => {
                const li = document.createElement('li');
                li.innerHTML = `<strong>Finding:</strong> ${escapeHtml(finding)}`;
                headersList.appendChild(li);
            });
        }
        const importantHeaders = ['From', 'To', 'Subject', 'Date', 'Message-ID', 'Return-Path', 'Attachments'];
        importantHeaders.forEach(key => {
            if (data.headers[key]) {
                const li = document.createElement('li');
                let val = Array.isArray(data.headers[key]) ? data.headers[key].join(', ') : data.headers[key];
                li.innerHTML = `<strong style="color:var(--accent-primary);">${key}:</strong> ${escapeHtml(val)}`;
                headersList.appendChild(li);
            }
        });

        // Render Body Preview
        const bodyPreview = document.getElementById('body-preview');
        if (bodyPreview) {
            bodyPreview.textContent = data.body || 'No body content parsed.';
        }

        // Render URLs Table
        document.getElementById('url-count').innerText = data.urls_found;
        const tbody = document.querySelector('#urls-table tbody');
        tbody.innerHTML = '';
        
        if (Object.keys(data.vt_results).length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No URLs extracted or scanned.</td></tr>';
        } else {
            for (const [url, stats] of Object.entries(data.vt_results)) {
                const tr = document.createElement('tr');
                
                let malClass = stats.malicious > 0 ? 'text-danger' : '';
                let susClass = stats.suspicious > 0 ? 'text-warning' : '';
                let statusMsg = stats.status || (stats.error ? `<span class="text-danger">${stats.error}</span>` : 'Scanned');
                
                let malCount = stats.malicious !== undefined ? stats.malicious : 0;
                let susCount = stats.suspicious !== undefined ? stats.suspicious : 0;
                let harmCount = stats.harmless !== undefined ? stats.harmless : 0;
                
                if (statusMsg.includes("Missing VT API Key") || statusMsg.includes("Skipped") || statusMsg.includes("Not found")) {
                    malCount = '-';
                    susCount = '-';
                    harmCount = '-';
                }
                
                tr.innerHTML = `
                    <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(url)}">
                        <a href="${escapeHtml(url)}" target="_blank" style="color: var(--accent-primary); text-decoration: none;">${escapeHtml(url)}</a>
                    </td>
                    <td class="${malClass}">${malCount}</td>
                    <td class="${susClass}">${susCount}</td>
                    <td>${harmCount}</td>
                    <td>${statusMsg}</td>
                `;
                tbody.appendChild(tr);
            }
        }

        results.classList.remove('hidden');
    }

    resetBtn.addEventListener('click', () => {
        results.classList.add('hidden');
        resetBtn.classList.add('hidden');
        uploadView.classList.remove('hidden');
        form.classList.remove('hidden');
        loading.classList.add('hidden');
        fileInput.value = '';
    });

    // Helper to prevent XSS in rendering
    function escapeHtml(unsafe) {
        if (!unsafe) return '';
        return String(unsafe)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
