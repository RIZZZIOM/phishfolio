/**
 * NestHunter - Nested Archive Analysis Tool
 * Frontend JavaScript with D3.js Tree Visualization
 */

// State management
let state = {
    analysisId: null,
    analysisData: null,
    selectedNode: null
};

// DOM Elements
const elements = {
    dropZone: document.getElementById('dropZone'),
    fileInput: document.getElementById('fileInput'),
    maxDepth: document.getElementById('maxDepth'),
    depthValue: document.getElementById('depthValue'),
    uploadSection: document.getElementById('uploadSection'),
    progressSection: document.getElementById('progressSection'),
    resultsSection: document.getElementById('resultsSection'),
    progressText: document.getElementById('progressText'),
    progressFill: document.getElementById('progressFill'),
    // Summary
    riskCard: document.getElementById('riskCard'),
    riskLevel: document.getElementById('riskLevel'),
    totalFiles: document.getElementById('totalFiles'),
    totalArchives: document.getElementById('totalArchives'),
    maxDepthReached: document.getElementById('maxDepthReached'),
    patternCount: document.getElementById('patternCount'),
    // Panels
    patternsList: document.getElementById('patternsList'),
    hashCollisions: document.getElementById('hashCollisions'),
    detailsContainer: document.getElementById('detailsContainer'),
    treeContainer: document.getElementById('treeContainer'),
    // Modal
    nodeModal: document.getElementById('nodeModal'),
    modalTitle: document.getElementById('modalTitle'),
    modalBody: document.getElementById('modalBody'),
    modalClose: document.getElementById('modalClose'),
    // Buttons
    exportBtn: document.getElementById('exportBtn'),
    newAnalysisBtn: document.getElementById('newAnalysisBtn'),
    expandAll: document.getElementById('expandAll'),
    collapseAll: document.getElementById('collapseAll'),
    resetView: document.getElementById('resetView')
};

// ===== File Upload =====

// Drag and drop handlers
elements.dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    elements.dropZone.classList.add('drag-over');
});

elements.dropZone.addEventListener('dragleave', () => {
    elements.dropZone.classList.remove('drag-over');
});

elements.dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    elements.dropZone.classList.remove('drag-over');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFileUpload(files[0]);
    }
});

elements.dropZone.addEventListener('click', () => {
    elements.fileInput.click();
});

elements.fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFileUpload(e.target.files[0]);
    }
});

// Depth slider
elements.maxDepth.addEventListener('input', (e) => {
    elements.depthValue.textContent = e.target.value;
});

// Handle file upload
async function handleFileUpload(file) {
    showProgress();
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('max_depth', elements.maxDepth.value);
    
    try {
        updateProgress('Uploading file...', 10);
        
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });
        
        updateProgress('Analyzing archive structure...', 40);
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Analysis failed');
        }
        
        updateProgress('Processing results...', 80);
        
        state.analysisId = data.id;
        state.analysisData = data;
        
        updateProgress('Rendering visualization...', 95);
        
        setTimeout(() => {
            showResults(data);
        }, 500);
        
    } catch (error) {
        alert('Error: ' + error.message);
        showUpload();
    }
}

// ===== UI State Management =====

function showUpload() {
    elements.uploadSection.classList.remove('hidden');
    elements.progressSection.classList.add('hidden');
    elements.resultsSection.classList.add('hidden');
}

function showProgress() {
    elements.uploadSection.classList.add('hidden');
    elements.progressSection.classList.remove('hidden');
    elements.resultsSection.classList.add('hidden');
}

function showResults(data) {
    elements.uploadSection.classList.add('hidden');
    elements.progressSection.classList.add('hidden');
    elements.resultsSection.classList.remove('hidden');
    
    renderResults(data);
}

function updateProgress(text, percent) {
    elements.progressText.textContent = text;
    elements.progressFill.style.width = percent + '%';
}

// ===== Results Rendering =====

function renderResults(data) {
    // Update summary cards
    const analysis = data.analysis;
    const extraction = data.extraction;
    
    // Risk level
    const riskLevel = analysis.risk_level;
    elements.riskLevel.textContent = riskLevel.toUpperCase();
    elements.riskCard.className = `card risk-card risk-${riskLevel}`;
    
    // Stats
    elements.totalFiles.textContent = extraction.total_files;
    elements.totalArchives.textContent = extraction.total_archives;
    elements.maxDepthReached.textContent = extraction.max_depth_reached;
    elements.patternCount.textContent = analysis.total_patterns;
    
    // Render tree
    renderTree(extraction.root);
    
    // Render patterns
    renderPatterns(analysis.patterns);
    
    // Render hash collisions
    renderHashCollisions(extraction.hash_collisions);
}

// ===== D3.js Tree Visualization =====

let treeRoot = null;
let treeSvg = null;
let treeG = null;
let zoom = null;

function renderTree(rootData) {
    const container = elements.treeContainer;
    const width = container.clientWidth;
    const height = container.clientHeight;
    
    // Clear previous
    d3.select('#treeSvg').selectAll('*').remove();
    
    // Create SVG
    treeSvg = d3.select('#treeSvg')
        .attr('width', width)
        .attr('height', height);
    
    // Add zoom behavior
    zoom = d3.zoom()
        .scaleExtent([0.1, 4])
        .on('zoom', (event) => {
            treeG.attr('transform', event.transform);
        });
    
    treeSvg.call(zoom);
    
    // Create main group
    treeG = treeSvg.append('g')
        .attr('transform', `translate(80, ${height / 2})`);
    
    // Create hierarchy
    treeRoot = d3.hierarchy(rootData, d => d.children);
    treeRoot.x0 = height / 2;
    treeRoot.y0 = 0;
    
    // Collapse children by default if more than 2 levels
    if (treeRoot.height > 2) {
        treeRoot.children?.forEach(collapse);
    }
    
    // Create tree layout
    updateTree(treeRoot);
}

function collapse(d) {
    if (d.children) {
        d._children = d.children;
        d._children.forEach(collapse);
        d.children = null;
    }
}

function expand(d) {
    if (d._children) {
        d.children = d._children;
        d._children = null;
    }
}

function expandAll(d) {
    expand(d);
    if (d.children) d.children.forEach(expandAll);
    if (d._children) d._children.forEach(expandAll);
}

function collapseAll(d) {
    if (d.children) {
        d.children.forEach(collapseAll);
        d._children = d.children;
        d.children = null;
    }
}

function updateTree(source) {
    const container = elements.treeContainer;
    const width = container.clientWidth;
    const height = container.clientHeight;
    
    const treeLayout = d3.tree()
        .size([height - 100, width - 200])
        .separation((a, b) => (a.parent === b.parent ? 1 : 2) / a.depth);
    
    const tree = treeLayout(treeRoot);
    const nodes = tree.descendants();
    const links = tree.links();
    
    // Normalize for fixed-depth
    nodes.forEach(d => {
        d.y = d.depth * 180;
    });
    
    // ===== Links =====
    const link = treeG.selectAll('.link')
        .data(links, d => d.target.data.id);
    
    const linkEnter = link.enter()
        .append('path')
        .attr('class', 'link')
        .attr('d', d => {
            const o = { x: source.x0 || 0, y: source.y0 || 0 };
            return diagonal(o, o);
        });
    
    link.merge(linkEnter)
        .transition()
        .duration(500)
        .attr('d', d => diagonal(d.source, d.target));
    
    link.exit()
        .transition()
        .duration(500)
        .attr('d', d => {
            const o = { x: source.x, y: source.y };
            return diagonal(o, o);
        })
        .remove();
    
    // ===== Nodes =====
    const node = treeG.selectAll('.node')
        .data(nodes, d => d.data.id);
    
    const nodeEnter = node.enter()
        .append('g')
        .attr('class', d => getNodeClass(d.data))
        .attr('transform', d => `translate(${source.y0 || 0}, ${source.x0 || 0})`)
        .on('click', (event, d) => {
            event.stopPropagation();
            toggleNode(d);
        })
        .on('dblclick', (event, d) => {
            event.stopPropagation();
            showNodeDetails(d.data);
        });
    
    nodeEnter.append('circle')
        .attr('r', 0)
        .attr('fill', d => getNodeColor(d.data))
        .attr('stroke', d => getNodeStroke(d.data))
        .attr('stroke-width', 2);
    
    nodeEnter.append('text')
        .attr('dy', '.35em')
        .attr('x', d => d.children || d._children ? -13 : 13)
        .attr('text-anchor', d => d.children || d._children ? 'end' : 'start')
        .text(d => truncateName(d.data.name, 25))
        .style('fill-opacity', 0);
    
    // Merge
    const nodeUpdate = nodeEnter.merge(node);
    
    nodeUpdate.transition()
        .duration(500)
        .attr('transform', d => `translate(${d.y}, ${d.x})`);
    
    nodeUpdate.select('circle')
        .transition()
        .duration(500)
        .attr('r', d => d.data.is_archive ? 10 : 7)
        .attr('fill', d => d._children ? '#f59e0b' : getNodeColor(d.data));
    
    nodeUpdate.select('text')
        .transition()
        .duration(500)
        .style('fill-opacity', 1)
        .attr('x', d => d.children || d._children ? -13 : 13)
        .attr('text-anchor', d => d.children || d._children ? 'end' : 'start');
    
    // Exit
    const nodeExit = node.exit()
        .transition()
        .duration(500)
        .attr('transform', d => `translate(${source.y}, ${source.x})`)
        .remove();
    
    nodeExit.select('circle')
        .attr('r', 0);
    
    nodeExit.select('text')
        .style('fill-opacity', 0);
    
    // Store positions
    nodes.forEach(d => {
        d.x0 = d.x;
        d.y0 = d.y;
    });
}

function diagonal(s, d) {
    return `M ${s.y} ${s.x}
            C ${(s.y + d.y) / 2} ${s.x},
              ${(s.y + d.y) / 2} ${d.x},
              ${d.y} ${d.x}`;
}

function toggleNode(d) {
    if (d.children) {
        d._children = d.children;
        d.children = null;
    } else {
        d.children = d._children;
        d._children = null;
    }
    updateTree(d);
}

function getNodeClass(data) {
    let className = 'node';
    if (data.is_archive) className += ' node-archive';
    else className += ' node-regular';
    if (data.suspicious_flags?.length > 0) className += ' node-suspicious';
    return className;
}

function getNodeColor(data) {
    if (data.suspicious_flags?.length > 0) return '#ef4444';
    if (data.is_archive) return '#3b82f6';
    
    const ext = data.name.split('.').pop()?.toLowerCase();
    const execExts = ['exe', 'dll', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'js'];
    if (execExts.includes(ext)) return '#f59e0b';
    
    return '#4b5563';
}

function getNodeStroke(data) {
    if (data.suspicious_flags?.length > 0) return '#dc2626';
    if (data.is_archive) return '#60a5fa';
    return '#6b7280';
}

function truncateName(name, maxLen) {
    if (name.length <= maxLen) return name;
    const ext = name.includes('.') ? '.' + name.split('.').pop() : '';
    const baseName = name.substring(0, maxLen - ext.length - 3);
    return baseName + '...' + ext;
}

// ===== Patterns Rendering =====

function renderPatterns(patterns) {
    if (!patterns || patterns.length === 0) {
        elements.patternsList.innerHTML = `
            <div class="no-patterns">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
                <h3>No Suspicious Patterns Detected</h3>
                <p>The archive appears clean of common malware delivery indicators.</p>
            </div>
        `;
        return;
    }
    
    const html = patterns.map(pattern => `
        <div class="pattern-item severity-${pattern.severity}">
            <div class="pattern-header">
                <span class="pattern-type">${pattern.pattern_type}</span>
                <span class="pattern-severity">${pattern.severity}</span>
            </div>
            <p class="pattern-description">${pattern.description}</p>
            ${pattern.path ? `<p class="pattern-path">${escapeHtml(pattern.path)}</p>` : ''}
        </div>
    `).join('');
    
    elements.patternsList.innerHTML = html;
}

// ===== Hash Collisions Rendering =====

function renderHashCollisions(collisions) {
    if (!collisions || Object.keys(collisions).length === 0) {
        elements.hashCollisions.innerHTML = `
            <div class="no-patterns">
                <p>No duplicate files detected across the archive.</p>
            </div>
        `;
        return;
    }
    
    const html = Object.entries(collisions).map(([hash, paths]) => `
        <div class="hash-item">
            <div class="hash-value">${hash}</div>
            <div class="hash-paths">
                ${paths.map(p => `<span>📄 ${escapeHtml(getFileName(p))}</span>`).join('')}
            </div>
        </div>
    `).join('');
    
    elements.hashCollisions.innerHTML = html;
}

// ===== Node Details =====

function showNodeDetails(data) {
    state.selectedNode = data;
    
    const html = `
        <div class="file-details">
            <h4>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    ${data.is_archive ? 
                        '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>' :
                        '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>'}
                </svg>
                ${escapeHtml(data.name)}
            </h4>
            <div class="details-grid">
                <div class="detail-item">
                    <label>Type</label>
                    <span>${data.file_type}</span>
                </div>
                <div class="detail-item">
                    <label>Size</label>
                    <span>${formatFileSize(data.size)}</span>
                </div>
                <div class="detail-item">
                    <label>Depth</label>
                    <span>${data.depth}</span>
                </div>
                <div class="detail-item">
                    <label>Is Archive</label>
                    <span>${data.is_archive ? 'Yes' : 'No'}</span>
                </div>
                <div class="detail-item">
                    <label>SHA-256</label>
                    <span>${data.sha256}</span>
                </div>
                <div class="detail-item">
                    <label>MD5</label>
                    <span>${data.md5}</span>
                </div>
            </div>
            ${data.suspicious_flags?.length > 0 ? `
                <div class="flags-list">
                    ${data.suspicious_flags.map(flag => `
                        <span class="flag-tag">⚠️ ${escapeHtml(flag)}</span>
                    `).join('')}
                </div>
            ` : ''}
            ${data.extraction_error ? `
                <div class="flags-list">
                    <span class="flag-tag">❌ ${escapeHtml(data.extraction_error)}</span>
                </div>
            ` : ''}
        </div>
    `;
    
    elements.detailsContainer.innerHTML = html;
    
    // Switch to details tab
    switchTab('details');
}

// ===== Tabs =====

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        const tabName = tab.dataset.tab;
        switchTab(tabName);
    });
});

function switchTab(tabName) {
    document.querySelectorAll('.tab').forEach(t => {
        t.classList.toggle('active', t.dataset.tab === tabName);
    });
    
    document.querySelectorAll('.tab-panel').forEach(p => {
        p.classList.toggle('active', p.id === tabName + 'Panel');
    });
}

// ===== Tree Controls =====

elements.expandAll.addEventListener('click', () => {
    if (treeRoot) {
        expandAll(treeRoot);
        updateTree(treeRoot);
    }
});

elements.collapseAll.addEventListener('click', () => {
    if (treeRoot) {
        treeRoot.children?.forEach(collapseAll);
        updateTree(treeRoot);
    }
});

elements.resetView.addEventListener('click', () => {
    if (treeSvg && zoom) {
        treeSvg.transition()
            .duration(500)
            .call(zoom.transform, d3.zoomIdentity);
    }
});

// ===== Actions =====

elements.exportBtn.addEventListener('click', () => {
    if (state.analysisId) {
        window.location.href = `/api/export/${state.analysisId}`;
    }
});

elements.newAnalysisBtn.addEventListener('click', () => {
    if (state.analysisId) {
        fetch(`/api/cleanup/${state.analysisId}`, { method: 'POST' })
            .catch(() => {});
    }
    
    state.analysisId = null;
    state.analysisData = null;
    state.selectedNode = null;
    
    elements.fileInput.value = '';
    showUpload();
});

// ===== Modal =====

elements.modalClose.addEventListener('click', () => {
    elements.nodeModal.classList.add('hidden');
});

elements.nodeModal.addEventListener('click', (e) => {
    if (e.target === elements.nodeModal) {
        elements.nodeModal.classList.add('hidden');
    }
});

// ===== Utilities =====

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function getFileName(path) {
    return path.split(/[/\\]/).pop() || path;
}

// ===== Window Resize =====

let resizeTimeout;
window.addEventListener('resize', () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(() => {
        if (state.analysisData) {
            renderTree(state.analysisData.extraction.root);
        }
    }, 250);
});

// ===== Initialize =====

console.log(`
╔═══════════════════════════════════════════════════════════╗
║                      NestHunter                           ║
║         Nested Archive Extraction & Analysis Tool         ║
╚═══════════════════════════════════════════════════════════╝
`);
