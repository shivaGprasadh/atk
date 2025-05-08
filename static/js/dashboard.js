/**
 * Dashboard.js
 * Contains functions specific to the dashboard functionality
 */

document.addEventListener('DOMContentLoaded', function() {
    // Toggle for compact view
    const compactViewToggle = document.getElementById('compact-view-toggle');
    if (compactViewToggle) {
        compactViewToggle.addEventListener('change', function() {
            const dashboard = document.getElementById('dashboard-container');
            if (dashboard) {
                if (this.checked) {
                    dashboard.classList.add('compact-view');
                    localStorage.setItem('dashboard-compact-view', 'true');
                } else {
                    dashboard.classList.remove('compact-view');
                    localStorage.setItem('dashboard-compact-view', 'false');
                }
            }
        });

        // Check if user previously set compact view
        if (localStorage.getItem('dashboard-compact-view') === 'true') {
            compactViewToggle.checked = true;
            const dashboard = document.getElementById('dashboard-container');
            if (dashboard) {
                dashboard.classList.add('compact-view');
            }
        }
    }

    // Update scan count
    updateScanCounts();

    // Set up auto-refresh if enabled
    const autoRefreshToggle = document.getElementById('auto-refresh-toggle');
    if (autoRefreshToggle) {
        let refreshInterval;

        autoRefreshToggle.addEventListener('change', function() {
            if (this.checked) {
                refreshInterval = setInterval(updateDashboardData, 30000); // Refresh every 30 seconds
                localStorage.setItem('dashboard-auto-refresh', 'true');
            } else {
                clearInterval(refreshInterval);
                localStorage.setItem('dashboard-auto-refresh', 'false');
            }
        });

        // Check if user previously enabled auto-refresh
        if (localStorage.getItem('dashboard-auto-refresh') === 'true') {
            autoRefreshToggle.checked = true;
            refreshInterval = setInterval(updateDashboardData, 30000);
        }
    }

    // Set up the time period selector
    const timePeriodSelect = document.getElementById('time-period-select');
    if (timePeriodSelect) {
        timePeriodSelect.addEventListener('change', function() {
            updateDashboardData(this.value);
            localStorage.setItem('dashboard-time-period', this.value);
        });

        // Check if user previously selected a time period
        const savedTimePeriod = localStorage.getItem('dashboard-time-period');
        if (savedTimePeriod) {
            timePeriodSelect.value = savedTimePeriod;
            updateDashboardData(savedTimePeriod);
        }
    }

    // Handle manual refresh button
    const refreshButton = document.getElementById('refresh-dashboard');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            // Show loading spinner on button
            this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Refreshing...';
            this.disabled = true;

            // Update dashboard data
            updateDashboardData().then(() => {
                // Restore button after update
                this.innerHTML = '<i class="fas fa-sync-alt"></i> Refresh';
                this.disabled = false;
            });
        });
    }
});

/**
 * Updates the scan counts displayed on the dashboard
 * In a real application, this would make an AJAX request to get the latest data
 */
function updateScanCounts() {
    // This is a placeholder. In a real app, this would make an AJAX request.
    console.log('Updating scan counts...');

    // The actual implementation would fetch data from the server and update UI elements
}

/**
 * Updates all dashboard data based on the selected time period
 * @param {string} timePeriod - The time period to filter data by (e.g., '7d', '30d', 'all')
 * @returns {Promise} A promise that resolves when the update is complete
 */
function updateDashboardData(timePeriod = '7d') {
    console.log(`Updating dashboard data for time period: ${timePeriod}`);

    // This is a placeholder. In a real app, this would make AJAX requests
    // to get updated data and refresh all charts and statistics.

    // For demonstration, we'll return a promise that resolves after a short delay
    return new Promise(resolve => {
        setTimeout(() => {
            // In a real app, this would update the charts with new data
            console.log('Dashboard data updated');
            resolve();
        }, 1000);
    });
}

/**
 * Handles vulnerability card click to show detailed information
 * @param {number} scanId - The ID of the scan to show details for
 */
function showVulnerabilityDetails(scanId) {
    // In a real app, this would show a modal or navigate to a details page
    console.log(`Showing vulnerability details for scan ID: ${scanId}`);

    // For demonstration, we'll show a SweetAlert modal
    Swal.fire({
        title: 'Vulnerability Details',
        text: `Detailed information for scan #${scanId} would be shown here.`,
        icon: 'info',
        confirmButtonText: 'Close'
    });
}

/**
 * Handles exporting dashboard data
 * @param {string} format - The export format (pdf, csv, json)
 */
function exportDashboardData(format) {
    console.log(`Exporting dashboard data in ${format} format`);

    // For demonstration, we'll show a SweetAlert modal
    Swal.fire({
        title: 'Export Dashboard',
        text: `Dashboard data would be exported in ${format.toUpperCase()} format.`,
        icon: 'success',
        confirmButtonText: 'OK'
    });
}