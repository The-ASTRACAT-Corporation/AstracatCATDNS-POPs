document.addEventListener('DOMContentLoaded', () => {
    const qpsValue = document.getElementById('qps-value');
    const totalQueries = document.getElementById('total-queries');
    const cacheProbation = document.getElementById('cache-probation');
    const cacheProtected = document.getElementById('cache-protected');
    const cpuUsage = document.getElementById('cpu-usage');
    const memUsage = document.getElementById('mem-usage');
    const goroutines = document.getElementById('goroutines');

    const qpsChartCtx = document.getElementById('qps-chart').getContext('2d');
    const cacheChartCtx = document.getElementById('cache-chart').getContext('2d');
    const cpuChartCtx = document.getElementById('cpu-chart').getContext('2d');
    const memChartCtx = document.getElementById('mem-chart').getContext('2d');

    const qpsChart = createLineChart(qpsChartCtx, 'QPS', 'rgba(75, 192, 192, 1)');
    const cacheChart = createLineChart(cacheChartCtx, 'Cache Load', 'rgba(153, 102, 255, 1)');
    const cpuChart = createLineChart(cpuChartCtx, 'CPU Usage', 'rgba(255, 99, 132, 1)');
    const memChart = createLineChart(memChartCtx, 'Memory Usage', 'rgba(54, 162, 235, 1)');

    const queryTypesChart = createPieChart(document.getElementById('query-types-chart').getContext('2d'), 'Query Types');
    const responseCodesChart = createBarChart(document.getElementById('response-codes-chart').getContext('2d'), 'Response Codes');

    function createLineChart(ctx, label, color) {
        return new Chart(ctx, {
            type: 'line',
            data: {
                labels: Array(60).fill(''),
                datasets: [{
                    label: label,
                    data: Array(60).fill(0),
                    borderColor: color,
                    borderWidth: 1,
                    fill: false,
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true,
                        max: label.includes('Usage') ? 100 : undefined
                    }
                }
            }
        });
    }

    async function fetchMetrics() {
        try {
            const response = await fetch('/metrics');
            const data = await response.json();

            qpsValue.textContent = data.qps.toFixed(2);
            totalQueries.textContent = data.total_queries;
            cacheProbation.textContent = data.cache_probation;
            cacheProtected.textContent = data.cache_protected;
            cpuUsage.textContent = `${data.cpu_usage.toFixed(2)}%`;
            memUsage.textContent = `${data.mem_usage.toFixed(2)}%`;
            goroutines.textContent = data.goroutine_count;

            updateChart(qpsChart, data.qps_history);
            updateChart(cacheChart, data.cache_load_history);
            updateChart(cpuChart, data.cpu_history);
            updateChart(memChart, data.mem_history);

            updateTopDomainsTable(document.getElementById('nx-domains-table').querySelector('tbody'), data.top_nx_domains, 'Count');
            updateTopDomainsTable(document.getElementById('latency-domains-table').querySelector('tbody'), data.top_latency_domains, 'Latency');

            updateStatChart(queryTypesChart, data.query_types, 'pie');
            updateStatChart(responseCodesChart, data.response_codes, 'bar');

        } catch (error) {
            console.error('Error fetching metrics:', error);
        }
    }

    function updateChart(chart, data) {
        chart.data.datasets[0].data = data;
        chart.update();
    }

    function updateTopDomainsTable(tbody, domains, valueType) {
        tbody.innerHTML = '';
        if (domains) {
            domains.forEach(item => {
                const row = document.createElement('tr');
                const domainCell = document.createElement('td');
                const valueCell = document.createElement('td');
                domainCell.textContent = item.domain;
                if (valueType === 'Count') {
                    valueCell.textContent = item.value;
                } else {
                    valueCell.textContent = item.value.toFixed(2);
                }
                row.appendChild(domainCell);
                row.appendChild(valueCell);
                tbody.appendChild(row);
            });
        }
    }

    function createPieChart(ctx, label) {
        return new Chart(ctx, {
            type: 'pie',
            data: {
                labels: [],
                datasets: [{
                    label: label,
                    data: [],
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 206, 86, 0.7)',
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(153, 102, 255, 0.7)',
                        'rgba(255, 159, 64, 0.7)'
                    ],
                }]
            }
        });
    }

    function createBarChart(ctx, label) {
        return new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: label,
                    data: [],
                    backgroundColor: 'rgba(75, 192, 192, 0.7)',
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
    }

    function updateStatChart(chart, data, chartType) {
        if (data) {
            const labels = data.map(item => item.name);
            const values = data.map(item => item.value);
            chart.data.labels = labels;
            chart.data.datasets[0].data = values;
            chart.update();
        }
    }

    setInterval(fetchMetrics, 2000);
    fetchMetrics();
});