/**
 * Dashboard functionality for Azure Drift Detector
 */

/**
 * Load data for the dashboard
 * @returns {Promise} Promise resolved when data is loaded
 */
function loadDashboardData() {
    return fetch('/api/dashboard/stats')
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch dashboard data');
            }
            return response.json();
        })
        .then(data => {
            // Update stats
            updateDashboardStats(data);
            
            // Update charts
            updateChangesChart(data.change_distribution);
            updateTimelineChart(data.timeline_data);
            
            // Update recent changes table
            updateRecentChangesTable(data.recent_changes_list);
            
            // Update timestamp
            document.getElementById('last-update').textContent = 
                `Last update: ${new Date().toLocaleTimeString()}`;
                
            return data;
        })
        .catch(error => {
            console.error('Error loading dashboard data:', error);
            document.getElementById('last-update').textContent = 
                `Last update failed: ${new Date().toLocaleTimeString()}`;
            throw error;
        });
}

/**
 * Update the dashboard statistics
 * @param {Object} data - Dashboard statistics data
 */
function updateDashboardStats(data) {
    // Update count cards
    document.getElementById('total-resources').textContent = data.total_resources || '0';
    document.getElementById('critical-changes').textContent = data.critical_changes || '0';
    document.getElementById('recent-changes').textContent = data.recent_changes || '0';
    document.getElementById('signin-events').textContent = data.signin_events || '0';
}

/**
 * Update the recent changes table
 * @param {Array} changes - List of recent changes
 */
function updateRecentChangesTable(changes) {
    const tableBody = document.getElementById('recent-changes-table');
    
    if (!changes || changes.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center">
                    <div class="py-4">
                        <i class="bi bi-check-circle fs-1 text-success mb-3"></i>
                        <p>No configuration changes detected.</p>
                    </div>
                </td>
            </tr>`;
        return;
    }
    
    let html = '';
    changes.forEach(change => {
        html += `
        <tr class="severity-${change.severity}">
            <td>${change.time}</td>
            <td>${escapeHtml(change.resource_name)}</td>
            <td>${escapeHtml(change.resource_type)}</td>
            <td>${escapeHtml(change.change_type)}</td>
            <td>${change.severity_badge}</td>
            <td>
                <button type="button" class="btn btn-sm btn-outline-info" 
                        onclick="viewChangeDetails(${change.id})"
                        data-bs-toggle="modal" data-bs-target="#changeDetailsModal">
                    <i class="bi bi-info-circle"></i>
                </button>
            </td>
        </tr>`;
    });
    
    tableBody.innerHTML = html;
}

/**
 * Refresh the dashboard data
 */
function refreshDashboard() {
    const refreshBtn = document.getElementById('refresh-btn');
    refreshBtn.disabled = true;
    refreshBtn.innerHTML = '<i class="bi bi-arrow-repeat me-1"></i> Refreshing...';
    
    loadDashboardData().finally(() => {
        refreshBtn.disabled = false;
        refreshBtn.innerHTML = '<i class="bi bi-arrow-clockwise me-1"></i> Refresh';
    });
}

/**
 * View details of a specific change
 * @param {number} changeId - ID of the change to view
 */
function viewChangeDetails(changeId) {
    // Show loading state in modal
    document.getElementById('changeDetailsBody').innerHTML = `
        <div class="d-flex justify-content-center py-5">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>`;
    
    fetch(`/api/changes/${changeId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch change details');
            }
            return response.json();
        })
        .then(data => {
            document.getElementById('changeDetailsTitle').textContent = 
                `Change Details - ${escapeHtml(data.resource_name)}`;
            document.getElementById('changeDetailsBody').innerHTML = formatChangeDetails(data);
        })
        .catch(error => {
            console.error('Error fetching change details:', error);
            document.getElementById('changeDetailsBody').innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i>
                    Error loading change details: ${escapeHtml(error.message)}
                </div>`;
        });
}

/**
 * Format change details for display in modal
 * @param {Object} data - Change details data
 * @returns {string} HTML for change details
 */
function formatChangeDetails(data) {
    let html = `
    <div class="row mb-3">
        <div class="col-md-6">
            <p><strong>Resource:</strong> ${escapeHtml(data.resource_name)}</p>
            <p><strong>Resource Type:</strong> ${escapeHtml(data.resource_type)}</p>
            <p><strong>Changed At:</strong> ${escapeHtml(data.time)}</p>
        </div>
        <div class="col-md-6">
            <p><strong>Source:</strong> ${escapeHtml(data.source)}</p>
            <p><strong>Severity:</strong> ${data.severity_badge}</p>
        </div>
    </div>
    <h5>Changes:</h5>
    <div class="table-responsive">
        <table class="table table-sm">
            <thead>
                <tr>
                    <th>Path</th>
                    <th>Type</th>
                    <th>Old Value</th>
                    <th>New Value</th>
                </tr>
            </thead>
            <tbody>`;
    
    if (!data.changes || data.changes.length === 0) {
        html += `
            <tr>
                <td colspan="4" class="text-center">No details available</td>
            </tr>`;
    } else {
        data.changes.forEach(change => {
            html += `
            <tr>
                <td><code>${escapeHtml(change.path)}</code></td>
                <td>${escapeHtml(change.type)}</td>
                <td><code>${escapeHtml(String(change.old_value || '-'))}</code></td>
                <td><code>${escapeHtml(String(change.new_value || '-'))}</code></td>
            </tr>`;
        });
    }
    
    html += `
            </tbody>
        </table>
    </div>`;
    
    return html;
}

/**
 * Escape HTML special characters for safe rendering
 * @param {string} unsafe - String that might contain HTML
 * @returns {string} Escaped string safe for insertion into HTML
 */
function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) {
        return '';
    }
    
    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Initialize dashboard when document is ready
document.addEventListener('DOMContentLoaded', function() {
    // Load initial data
    loadDashboardData();
    
    // Set up auto-refresh every 5 minutes
    setInterval(loadDashboardData, 5 * 60 * 1000);
});
