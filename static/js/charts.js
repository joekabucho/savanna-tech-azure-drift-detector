/**
 * Chart.js utility functions for Azure Drift Detector
 */

/**
 * Update the changes distribution chart with new data
 * @param {Object} distributionData - Object with severity counts
 */
function updateChangesChart(distributionData) {
    // Get the chart canvas
    const chartCanvas = document.getElementById('changesChart');
    
    // If chart instance already exists, destroy it
    if (window.changesChartInstance) {
        window.changesChartInstance.destroy();
    }
    
    // Create chart data from distribution data
    const labels = [];
    const data = [];
    const backgroundColors = [];
    
    // Add data points in specific order
    if ('critical' in distributionData) {
        labels.push('Critical');
        data.push(distributionData.critical);
        backgroundColors.push('#dc3545'); // Danger/red
    }
    
    if ('high' in distributionData) {
        labels.push('High');
        data.push(distributionData.high);
        backgroundColors.push('#fd7e14'); // Orange
    }
    
    if ('medium' in distributionData) {
        labels.push('Medium');
        data.push(distributionData.medium);
        backgroundColors.push('#ffc107'); // Warning/yellow
    }
    
    if ('low' in distributionData) {
        labels.push('Low');
        data.push(distributionData.low);
        backgroundColors.push('#0dcaf0'); // Info/blue
    }
    
    // Create the chart
    window.changesChartInstance = new Chart(chartCanvas, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#f8f9fa' // Light text for dark theme
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.formattedValue;
                            const total = context.dataset.data.reduce((acc, val) => acc + val, 0);
                            const percentage = Math.round((context.raw / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Update the timeline chart with new data
 * @param {Object} timelineData - Object with dates and counts
 */
function updateTimelineChart(timelineData) {
    // Get the chart canvas
    const chartCanvas = document.getElementById('timelineChart');
    
    // If chart instance already exists, destroy it
    if (window.timelineChartInstance) {
        window.timelineChartInstance.destroy();
    }
    
    // Prepare chart data
    const labels = Object.keys(timelineData);
    const criticalData = [];
    const highData = [];
    const mediumData = [];
    const lowData = [];
    
    // Process timeline data
    labels.forEach(date => {
        criticalData.push(timelineData[date].critical || 0);
        highData.push(timelineData[date].high || 0);
        mediumData.push(timelineData[date].medium || 0);
        lowData.push(timelineData[date].low || 0);
    });
    
    // Create the chart
    window.timelineChartInstance = new Chart(chartCanvas, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Critical',
                    data: criticalData,
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    fill: true,
                    tension: 0.3
                },
                {
                    label: 'High',
                    data: highData,
                    borderColor: '#fd7e14',
                    backgroundColor: 'rgba(253, 126, 20, 0.1)',
                    fill: true,
                    tension: 0.3
                },
                {
                    label: 'Medium',
                    data: mediumData,
                    borderColor: '#ffc107',
                    backgroundColor: 'rgba(255, 193, 7, 0.1)',
                    fill: true,
                    tension: 0.3
                },
                {
                    label: 'Low',
                    data: lowData,
                    borderColor: '#0dcaf0',
                    backgroundColor: 'rgba(13, 202, 240, 0.1)',
                    fill: true,
                    tension: 0.3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    ticks: {
                        color: '#adb5bd' // Lighter text for dark theme
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#adb5bd' // Lighter text for dark theme
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#f8f9fa' // Light text for dark theme
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            }
        }
    });
}

/**
 * Create a resource distribution chart
 * @param {Object} resourceData - Object with resource type counts
 * @param {string} canvasId - Canvas ID to render chart on
 */
function createResourceDistributionChart(resourceData, canvasId) {
    // Get the chart canvas
    const chartCanvas = document.getElementById(canvasId);
    
    // If no canvas exists, return
    if (!chartCanvas) return;
    
    // If chart instance already exists, destroy it
    if (window[canvasId + 'ChartInstance']) {
        window[canvasId + 'ChartInstance'].destroy();
    }
    
    // Prepare chart data
    const labels = Object.keys(resourceData);
    const data = Object.values(resourceData);
    
    // Generate colors
    const backgroundColors = [
        '#3498db', '#2ecc71', '#9b59b6', '#e74c3c', 
        '#f1c40f', '#1abc9c', '#34495e', '#e67e22'
    ];
    
    // Create the chart
    window[canvasId + 'ChartInstance'] = new Chart(chartCanvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Resources',
                data: data,
                backgroundColor: backgroundColors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    ticks: {
                        color: '#adb5bd' // Lighter text for dark theme
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#adb5bd' // Lighter text for dark theme
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

/**
 * Create a source distribution chart (pie)
 * @param {Object} sourceData - Object with source counts
 * @param {string} canvasId - Canvas ID to render chart on
 */
function createSourceDistributionChart(sourceData, canvasId) {
    // Get the chart canvas
    const chartCanvas = document.getElementById(canvasId);
    
    // If no canvas exists, return
    if (!chartCanvas) return;
    
    // If chart instance already exists, destroy it
    if (window[canvasId + 'ChartInstance']) {
        window[canvasId + 'ChartInstance'].destroy();
    }
    
    // Prepare chart data
    const labels = Object.keys(sourceData);
    const data = Object.values(sourceData);
    
    // Generate colors
    const backgroundColors = [
        '#007bff', '#28a745', '#fd7e14', '#6f42c1'
    ];
    
    // Create the chart
    window[canvasId + 'ChartInstance'] = new Chart(chartCanvas, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#f8f9fa' // Light text for dark theme
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.formattedValue;
                            const total = context.dataset.data.reduce((acc, val) => acc + val, 0);
                            const percentage = Math.round((context.raw / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}
