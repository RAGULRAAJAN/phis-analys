document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const form = document.getElementById('upload-form');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const resetBtn = document.getElementById('reset-btn');

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
            loading.classList.add('hidden');
            if (data.error) {
                alert('Error: ' + data.error);
                form.classList.remove('hidden');
            } else {
                renderResults(data);
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
        badge.innerText = `Risk: ${risk.risk_level}`;
        badge.className = `badge-${risk.risk_level.toLowerCase()}`;
        
        // Color the circle based on risk
        circle.style.stroke = `var(--${risk.risk_level.toLowerCase()})`;

        // Render Headers
        const headersList = document.getElementById('headers-list');
        headersList.innerHTML = '';
        const importantHeaders = ['From', 'To', 'Subject', 'Date', 'Message-ID'];
        importantHeaders.forEach(key => {
            if (data.headers[key]) {
                const li = document.createElement('li');
                li.innerHTML = `<strong>${key}:</strong> ${escapeHtml(data.headers[key])}`;
                headersList.appendChild(li);
            }
        });

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
                
                tr.innerHTML = `
                    <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(url)}">
                        <a href="${escapeHtml(url)}" target="_blank" style="color: var(--accent-cyan); text-decoration: none;">${escapeHtml(url)}</a>
                    </td>
                    <td class="${malClass}">${stats.malicious || 0}</td>
                    <td class="${susClass}">${stats.suspicious || 0}</td>
                    <td>${stats.harmless || 0}</td>
                    <td>${statusMsg}</td>
                `;
                tbody.appendChild(tr);
            }
        }

        results.classList.remove('hidden');
    }

    resetBtn.addEventListener('click', () => {
        results.classList.add('hidden');
        form.classList.remove('hidden');
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
