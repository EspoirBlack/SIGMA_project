/* ========================================
   SIGMA Security Monitor - Main JavaScript
   ======================================== */

// Global variables
let socket = null;
let refreshInterval = null;
let autoRefresh = true;

// ========================================
// WebSocket Connection
// ========================================

function initializeWebSocket() {
    socket = io();
    
    socket.on('connect', function() {
        console.log('WebSocket connected to server');
        showToast('Connected to server', 'success');
        requestUpdate();
    });
    
    socket.on('disconnect', function() {
        console.log('WebSocket disconnected');
        showToast('Disconnected from server', 'warning');
    });
    
    socket.on('system_update', function(data) {
        if (data.stats) {
            if (typeof window.updateSystemStats === 'function') {
                window.updateSystemStats(data.stats);
            }
            if (typeof window.updateCPUInfo === 'function') {
                window.updateCPUInfo(data.stats);
            }
        }
        if (data.alerts && typeof window.updateAlertsList === 'function') {
            window.updateAlertsList(data.alerts);
        }
        if (data.connections && typeof window.updateConnectionStats === 'function') {
            window.updateConnectionStats(data.connections);
        }
        if (typeof window.loadTopProcesses === 'function') {
            window.loadTopProcesses();
        }
    });
    
    socket.on('new_alerts', function(data) {
        if (data.count > 0) {
            showToast(`${data.count} new alert(s) detected!`, 'warning');
            if (typeof window.refreshDashboard === 'function') {
                window.refreshDashboard();
            }
        }
    });
}

function requestUpdate() {
    if (socket && socket.connected) {
        socket.emit('request_update');
    }
}

// ========================================
// Dashboard Functions
// ========================================

function updateSystemStats(stats) {
    // CPU
    const cpu = stats.cpu || {};
    const cpuPercent = cpu.percent || 0;
    const cpuElement = document.getElementById('cpu-percent');
    const cpuProgress = document.getElementById('cpu-progress');
    if (cpuElement) cpuElement.innerHTML = cpuPercent + '%';
    if (cpuProgress) cpuProgress.style.width = cpuPercent + '%';
    
    const loadElement = document.getElementById('cpu-load');
    if (loadElement) loadElement.innerHTML = `Load: ${cpu.load_1min || 0}`;
    
    const times = cpu.times || {};
    const userElement = document.getElementById('cpu-user');
    const systemElement = document.getElementById('cpu-system');
    const idleElement = document.getElementById('cpu-idle');
    if (userElement) userElement.innerHTML = (times.user || 0) + '%';
    if (systemElement) systemElement.innerHTML = (times.system || 0) + '%';
    if (idleElement) idleElement.innerHTML = (times.idle || 0) + '%';
    
    // Memory
    const mem = stats.memory || {};
    const memPercent = mem.percent || 0;
    const memPercentElement = document.getElementById('memory-percent');
    const memProgress = document.getElementById('memory-progress');
    if (memPercentElement) memPercentElement.innerHTML = memPercent + '%';
    if (memProgress) memProgress.style.width = memPercent + '%';
    
    const memUsed = document.getElementById('memory-used');
    const memTotal = document.getElementById('memory-total');
    if (memUsed) memUsed.innerHTML = (mem.used_gb || 0) + 'GB';
    if (memTotal) memTotal.innerHTML = (mem.total_gb || 0) + 'GB';
    
    // Uptime
    const sys = stats.system || {};
    const uptimeDays = document.getElementById('uptime-days');
    const uptimeHours = document.getElementById('uptime-hours-minutes');
    const bootTime = document.getElementById('boot-time');
    
    if (uptimeDays) uptimeDays.innerHTML = sys.uptime_days || 0;
    if (uptimeHours) uptimeHours.innerHTML = (sys.uptime_hours || 0) + 'h ' + (sys.uptime_minutes || 0) + 'm';
    if (bootTime) bootTime.innerHTML = sys.boot_time || 'Unknown';
}

function updateCPUInfo(stats) {
    const cpu = stats.cpu || {};
    const coresContainer = document.getElementById('cpu-cores-container');
    if (!coresContainer) return;
    
    if (cpu.percent_per_core && cpu.percent_per_core.length > 0) {
        let coresHtml = '';
        cpu.percent_per_core.forEach((core, index) => {
            const color = core > 80 ? '#e74c3c' : (core > 50 ? '#f39c12' : '#27ae60');
            coresHtml += `
                <div class="text-center" style="flex: 1; min-width: 50px;">
                    <div class="core-bar" style="height: 80px; background-color: #ecf0f1; border-radius: 6px; overflow: hidden; display: flex; flex-direction: column; justify-content: flex-end;">
                        <div class="core-fill" style="height: ${core}%; background-color: ${color}; transition: height 0.5s ease; display: flex; align-items: center; justify-content: center; font-size: 0.7rem; font-weight: bold; color: white;">
                            <span>${core}%</span>
                        </div>
                    </div>
                    <div class="small mt-1">Core ${index}</div>
                </div>
            `;
        });
        coresContainer.innerHTML = coresHtml;
    } else {
        coresContainer.innerHTML = '<div class="col-12 text-center text-muted">No CPU core data available</div>';
    }
}

function updateAlertsList(alerts) {
    const container = document.getElementById('alerts-container');
    if (!container) return;
    
    if (alerts && alerts.length > 0) {
        let html = '';
        alerts.slice(0, 8).forEach(alert => {
            const severity = alert.severity || 'LOW';
            const severityClass = severity === 'HIGH' ? 'alert-high' : (severity === 'MEDIUM' ? 'alert-medium' : 'alert-low');
            const badgeClass = severity === 'HIGH' ? 'danger' : (severity === 'MEDIUM' ? 'warning' : 'info');
            
            html += `
                <div class="list-group-item alert-item ${severityClass}">
                    <div class="d-flex justify-content-between align-items-center">
                        <strong>${escapeHtml(alert.rule_name)}</strong>
                        <span class="badge bg-${badgeClass}">${severity}</span>
                    </div>
                    <small class="text-muted">${formatTimestamp(alert.timestamp)}</small>
                    <div class="small mt-1">${escapeHtml((alert.details || '').substring(0, 120))}</div>
                </div>
            `;
        });
        container.innerHTML = html;
    } else {
        container.innerHTML = '<div class="text-center py-4 text-muted"><i class="fas fa-check-circle fa-2x mb-2"></i><br>No recent alerts</div>';
    }
}

function updateConnectionStats(connStats) {
    if (!connStats) return;
    const connCount = document.getElementById('conn-count');
    const connEstablished = document.getElementById('conn-established');
    const connListening = document.getElementById('conn-listening');
    
    if (connCount) connCount.innerHTML = connStats.total || 0;
    if (connEstablished) connEstablished.innerHTML = connStats.established || 0;
    if (connListening) connListening.innerHTML = connStats.listening || 0;
}

// ========================================
// Top Connections Functions
// ========================================

function loadTopConnections() {
    fetch('/api/connections/all')
        .then(response => response.json())
        .then(data => {
            const container = document.getElementById('top-connections-tbody');
            if (!container) return;
            
            if (data.success && data.data && data.data.length > 0) {
                const connections = data.data.slice(0, 8);
                let html = '';
                connections.forEach(conn => {
                    let riskIcon = '';
                    let riskClass = '';
                    const port = conn.remote_port;
                    if (port && [4444, 1337, 31337].includes(port)) {
                        riskIcon = '<i class="fas fa-skull-crosswalk risk-high"></i>';
                        riskClass = 'risk-high';
                    } else if (port && [5555, 6666, 6667].includes(port)) {
                        riskIcon = '<i class="fas fa-exclamation-triangle risk-medium"></i>';
                        riskClass = 'risk-medium';
                    } else {
                        riskIcon = '<i class="fas fa-check-circle risk-low"></i>';
                        riskClass = 'risk-low';
                    }
                    
                    html += `
                        <tr class="connection-row" onclick="window.location.href='/connections'">
                            <td><small>${escapeHtml(conn.process || 'Unknown')}</small>   ..
                             Was<code><small>${escapeHtml(conn.remote_ip || 'N/A')}</small></code>   ..
                             Was<small>${escapeHtml(conn.remote_port || 'N/A')}</small>   ..
                             Was<span class="badge ${conn.status === 'ESTABLISHED' ? 'bg-success' : (conn.status === 'LISTEN' ? 'bg-info' : 'bg-secondary')}">${escapeHtml(conn.status || 'N/A')}</span>   ..
                            <td class="text-center ${riskClass}">${riskIcon}..
                          </tbody>
                    `;
                });
                container.innerHTML = html;
            } else {
                container.innerHTML = '.<td colspan="5" class="text-center py-4 text-muted"><i class="fas fa-plug fa-2x mb-2"></i><br>No active connections.';
            }
        });
}

// ========================================
// Top Processes Functions
// ========================================

function loadTopProcesses() {
    fetch('/api/processes/all')
        .then(response => response.json())
        .then(data => {
            const container = document.getElementById('top-processes-tbody');
            if (!container) return;
            
            if (data.success && data.data && data.data.length > 0) {
                const processes = [...data.data]
                    .sort((a, b) => (b.cpu_percent || 0) - (a.cpu_percent || 0))
                    .slice(0, 8);
                
                let html = '';
                processes.forEach(proc => {
                    const cpuPercent = proc.cpu_percent || 0;
                    const memoryPercent = proc.memory_percent || 0;
                    const memoryMB = proc.memory_mb || 0;
                    
                    let cpuColorClass = '';
                    if (cpuPercent > 50) cpuColorClass = 'text-danger fw-bold';
                    else if (cpuPercent > 25) cpuColorClass = 'text-warning';
                    else cpuColorClass = 'text-success';
                    
                    let memColorClass = '';
                    if (memoryPercent > 50) memColorClass = 'text-danger';
                    else if (memoryPercent > 25) memColorClass = 'text-warning';
                    else memColorClass = 'text-success';
                    
                    const suspiciousProcesses = ['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'rundll32.exe', 'regsvr32.exe'];
                    const isSuspicious = suspiciousProcesses.includes(proc.name?.toLowerCase());
                    
                    html += `
                        <tr class="process-row" onclick="window.location.href='/processes'">
                             ..
                                <i class="fas ${isSuspicious ? 'fa-exclamation-triangle text-warning' : 'fa-microchip'} me-1"></i>
                                <strong>${escapeHtml(proc.name || 'Unknown')}</strong>
                                ${isSuspicious ? '<span class="badge bg-warning ms-1">!</span>' : ''}
                              ..
                              ..<small>${proc.pid || 'N/A'}</small>..
                            <td class="${cpuColorClass}"><strong>${cpuPercent.toFixed(1)}%</strong>..
                            <td class="${memColorClass}">${memoryPercent.toFixed(1)}%..
                              ..<small>${memoryMB.toFixed(0)} MB</small>..
                              ..<small>${escapeHtml(proc.username || 'Unknown')}</small>..
                              ..
                                ${isSuspicious ? 
                                    '<span class="badge bg-warning text-dark">SUSPICIOUS</span>' : 
                                    '<span class="badge bg-success">RUNNING</span>'
                                }
                              ..
                          </tr>
                    `;
                });
                container.innerHTML = html;
            } else {
                container.innerHTML = '.<td colspan="7" class="text-center py-4 text-muted"><i class="fas fa-microchip fa-2x mb-2"></i><br>No processes found.';
            }
        })
        .catch(error => {
            console.error('Error loading top processes:', error);
            const container = document.getElementById('top-processes-tbody');
            if (container) {
                container.innerHTML = '.<td colspan="7" class="text-center py-4 text-danger"><i class="fas fa-exclamation-triangle"></i> Failed to load processes.';
            }
        });
}

// ========================================
// Export Functions
// ========================================

function exportAlerts() {
    window.location.href = '/api/alerts/export';
}

function exportToCSV(data, filename) {
    if (!data || data.length === 0) return;
    
    const headers = Object.keys(data[0]);
    const csvRows = [headers.join(',')];
    
    for (const row of data) {
        const values = headers.map(header => {
            let value = row[header] || '';
            if (typeof value === 'string' && (value.includes(',') || value.includes('"'))) {
                value = `"${value.replace(/"/g, '""')}"`;
            }
            return value;
        });
        csvRows.push(values.join(','));
    }
    
    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ========================================
// Toast Notifications
// ========================================

function showToast(message, type = 'info') {
    const toastId = 'toast-' + Date.now();
    const icon = type === 'success' ? 'check-circle' : 
                 type === 'warning' ? 'exclamation-triangle' : 
                 type === 'error' ? 'times-circle' : 'info-circle';
    
    const colors = {
        success: '#27ae60',
        warning: '#f39c12',
        error: '#e74c3c',
        info: '#3498db'
    };
    
    const toast = document.createElement('div');
    toast.id = toastId;
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: white;
        border-left: 4px solid ${colors[type] || colors.info};
        padding: 12px 20px;
        margin-top: 10px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        animation: slideIn 0.3s ease;
        display: flex;
        align-items: center;
        gap: 10px;
    `;
    
    toast.innerHTML = `
        <i class="fas fa-${icon}" style="color: ${colors[type] || colors.info};"></i>
        <span>${escapeHtml(message)}</span>
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// ========================================
// Helper Functions
// ========================================

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    try {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = Math.floor((now - date) / 1000);
        
        if (diff < 60) return `${diff} seconds ago`;
        if (diff < 3600) return `${Math.floor(diff / 60)} minutes ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)} hours ago`;
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    } catch {
        return timestamp;
    }
}

function showLoading() {
    const overlay = document.getElementById('spinner-overlay');
    if (overlay) overlay.classList.add('active');
}

function hideLoading() {
    const overlay = document.getElementById('spinner-overlay');
    if (overlay) overlay.classList.remove('active');
}

// ========================================
// Auto-refresh Control
// ========================================

function startAutoRefresh() {
    if (refreshInterval) clearInterval(refreshInterval);
    refreshInterval = setInterval(requestUpdate, 5000);
}

function stopAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
    }
}

function toggleAutoRefresh() {
    autoRefresh = !autoRefresh;
    if (autoRefresh) {
        startAutoRefresh();
        showToast('Auto-refresh enabled', 'success');
    } else {
        stopAutoRefresh();
        showToast('Auto-refresh disabled', 'info');
    }
}

// ========================================
// Dark Mode Toggle
// ========================================

function toggleDarkMode() {
    document.body.classList.toggle('dark-mode');
    const isDark = document.body.classList.contains('dark-mode');
    localStorage.setItem('sigma-dark-mode', isDark);
    
    const icon = document.querySelector('.dark-mode-toggle i');
    if (icon) {
        icon.className = isDark ? 'fas fa-sun' : 'fas fa-moon';
    }
    
    showToast(`Dark mode ${isDark ? 'enabled' : 'disabled'}`, 'info');
}

function initializeDarkMode() {
    const savedMode = localStorage.getItem('sigma-dark-mode') === 'true';
    if (savedMode) {
        document.body.classList.add('dark-mode');
    }
    
    if (!document.querySelector('.dark-mode-toggle')) {
        const toggle = document.createElement('div');
        toggle.className = 'dark-mode-toggle';
        toggle.style.cssText = `
            position: fixed;
            bottom: 20px;
            left: 20px;
            background: white;
            border-radius: 50%;
            width: 45px;
            height: 45px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
            z-index: 9998;
        `;
        toggle.innerHTML = `<i class="fas ${savedMode ? 'fa-sun' : 'fa-moon'}"></i>`;
        toggle.onclick = toggleDarkMode;
        document.body.appendChild(toggle);
    }
}

// ========================================
// Alert Badge Update
// ========================================

function updateAlertBadge(count) {
    const badge = document.getElementById('alert-badge');
    const countBadge = document.getElementById('alert-count-badge');
    if (badge) {
        if (count > 0) {
            badge.textContent = count > 99 ? '99+' : count;
            badge.style.display = 'inline-block';
        } else {
            badge.style.display = 'none';
        }
    }
    if (countBadge) {
        if (count > 0) {
            countBadge.textContent = count;
            countBadge.style.display = 'inline-block';
        } else {
            countBadge.style.display = 'none';
        }
    }
}

function updateAlertBadgeFromStats() {
    fetch('/api/alerts/stats')
        .then(response => response.json())
        .then(data => {
            if (data.success && data.data) {
                const total = data.data.total || 0;
                updateAlertBadge(total);
            }
        })
        .catch(error => console.error('Error updating alert badge:', error));
}

// ========================================
// Initialize
// ========================================

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    body.dark-mode {
        background-color: #0f0f1a;
        color: #e0e0e0;
    }
    
    body.dark-mode .card {
        background-color: #1a1f2e;
        border-color: #2d2d44;
    }
    
    body.dark-mode .list-group-item {
        background-color: #1a1f2e;
        border-color: #2d2d44;
        color: #e0e0e0;
    }
    
    body.dark-mode .core-bar {
        background-color: #2d2d44;
    }
    
    body.dark-mode .dark-mode-toggle {
        background-color: #1a1f2e;
        color: #e0e0e0;
        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    }
    
    body.dark-mode .table {
        color: #e0e0e0;
    }
    
    body.dark-mode .table-striped > tbody > tr:nth-of-type(odd) {
        background-color: rgba(255, 255, 255, 0.05);
    }
    
    body.dark-mode .process-detail {
        background-color: #1a1f2e;
    }
    
    body.dark-mode .alert-secondary {
        background-color: #2d2d44;
        border-color: #3d3d5a;
        color: #e0e0e0;
    }
    
    body.dark-mode .toast-notification {
        background-color: #1a1f2e;
        color: #e0e0e0;
    }
    
    .process-row, .connection-row {
        transition: all 0.2s ease;
        cursor: pointer;
    }
    
    .process-row:hover, .connection-row:hover {
        background-color: rgba(52, 152, 219, 0.1);
        transform: translateX(3px);
    }
`;
document.head.appendChild(style);

document.addEventListener('DOMContentLoaded', function() {
    initializeDarkMode();
    initializeWebSocket();
    startAutoRefresh();
    
    // Load initial data
    if (typeof loadAlertStats === 'function') loadAlertStats();
    if (typeof loadTopConnections === 'function') loadTopConnections();
    if (typeof loadTopProcesses === 'function') loadTopProcesses();
    if (typeof updateAlertBadgeFromStats === 'function') updateAlertBadgeFromStats();
    
    console.log('SIGMA JavaScript initialized');
    
    setInterval(updateAlertBadgeFromStats, 30000);
});

// Export functions for global use
window.refreshData = requestUpdate;
window.exportAlerts = exportAlerts;
window.toggleAutoRefresh = toggleAutoRefresh;
window.showToast = showToast;
window.updateAlertBadge = updateAlertBadge;
window.loadTopConnections = loadTopConnections;
window.loadTopProcesses = loadTopProcesses;
window.updateSystemStats = updateSystemStats;
window.updateCPUInfo = updateCPUInfo;
window.updateAlertsList = updateAlertsList;
window.updateConnectionStats = updateConnectionStats;
window.refreshDashboard = function() {
    requestUpdate();
    if (typeof loadAlertStats === 'function') loadAlertStats();
    if (typeof loadTopConnections === 'function') loadTopConnections();
    if (typeof loadTopProcesses === 'function') loadTopProcesses();
};