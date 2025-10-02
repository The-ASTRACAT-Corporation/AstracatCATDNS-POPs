document.addEventListener('DOMContentLoaded', () => {
    const qpsValue = document.getElementById('qps-value');
    const totalQueries = document.getElementById('total-queries');
    const cacheProbation = document.getElementById('cache-probation');
    const cacheProtected = document.getElementById('cache-protected');

    const qpsChartCtx = document.getElementById('qps-chart').getContext('2d');
    const cacheChartCtx = document.getElementById('cache-chart').getContext('2d');

    const qpsChart = new Chart(qpsChartCtx, {
        type: 'line',
        data: {
            labels: Array(60).fill(''),
            datasets: [{
                label: 'QPS',
                data: Array(60).fill(0),
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1,
                fill: false,
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    const cacheChart = new Chart(cacheChartCtx, {
        type: 'line',
        data: {
            labels: Array(60).fill(''),
            datasets: [{
                label: 'Cache Load',
                data: Array(60).fill(0),
                borderColor: 'rgba(153, 102, 255, 1)',
                borderWidth: 1,
                fill: false,
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    async function fetchMetrics() {
        try {
            const response = await fetch('/metrics');
            const data = await response.json();

            qpsValue.textContent = data.qps.toFixed(2);
            totalQueries.textContent = data.total_queries;
            cacheProbation.textContent = data.cache_probation;
            cacheProtected.textContent = data.cache_protected;

            updateChart(qpsChart, data.qps_history);
            updateChart(cacheChart, data.cache_load_history);

        } catch (error) {
            console.error('Error fetching metrics:', error);
        }
    }

    function updateChart(chart, data) {
        chart.data.datasets[0].data = data;
        chart.update();
    }

    setInterval(fetchMetrics, 1000);
    fetchMetrics();
});