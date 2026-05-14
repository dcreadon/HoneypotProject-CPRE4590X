import json
import os
import time
from collections import Counter

import requests


# --- CONFIGURATION ---
INPUT_FILE = "ip_history.json"
OUTPUT_HTML = "honeypot_dashboard.html"
GEO_CACHE_FILE = "geo_cache.json"

# ip-api.com free tier allows 45 requests per minute.
GEO_RATE_LIMIT_SECONDS = 1.5


def load_json(path, default):
    """Load JSON from disk, returning default when the file is missing or invalid."""
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"[!] Warning: {path} is not valid JSON. Using default value.")
        return default


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def get_location(ip, geo_cache):
    """Fetch location data for an IP address, using a local cache when possible."""
    if ip in geo_cache:
        return geo_cache[ip]

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        response.raise_for_status()
        data = response.json()

        if data.get("status") == "success":
            result = {
                "city": data.get("city") or "Unknown",
                "country": data.get("country") or "Unknown",
                "isp": data.get("isp") or "Unknown",
            }
        else:
            result = {"city": "Unknown", "country": "Unknown", "isp": "Unknown"}

    except requests.RequestException:
        result = {"city": "Error", "country": "Error", "isp": "Error"}
    except ValueError:
        result = {"city": "Error", "country": "Error", "isp": "Error"}

    geo_cache[ip] = result
    time.sleep(GEO_RATE_LIMIT_SECONDS)
    return result


def normalize_timeline(timeline):
    """Keep only the fields the dashboard needs and tolerate malformed records."""
    if not isinstance(timeline, list):
        return []

    normalized = []
    for event in timeline:
        if not isinstance(event, dict):
            continue

        normalized.append(
            {
                "timestamp": str(event.get("timestamp") or ""),
                "eventid": str(event.get("eventid") or "unknown"),
                "message": str(event.get("message") or ""),
                "input": str(event.get("input") or ""),
            }
        )

    return normalized


def build_html(processed_ips, country_stats, event_stats):
    """Build a self-contained HTML dashboard."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Honeypot Forensic Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg: #0d1117;
            --card: #161b22;
            --card-hover: #1c2128;
            --border: #30363d;
            --text: #c9d1d9;
            --muted: #8b949e;
            --accent: #58a6ff;
            --cmd: #79c0ff;
            --success: #238636;
            --warning: #d29922;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family: "Segoe UI", Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            padding: 20px;
        }}

        .container {{
            max-width: 1300px;
            margin: 0 auto;
        }}

        h1 {{
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
            margin: 0 0 20px;
            font-size: 1.7rem;
        }}

        h2, h3 {{
            margin-top: 0;
        }}

        .summary-row {{
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }}

        .summary-card,
        .chart-card,
        .registry-card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
        }}

        .summary-card {{
            padding: 16px;
        }}

        .summary-label {{
            display: block;
            color: var(--muted);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            margin-bottom: 8px;
        }}

        .summary-value {{
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--accent);
        }}

        .charts-row {{
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }}

        .chart-card {{
            padding: 20px;
            height: 360px;
            display: flex;
            flex-direction: column;
        }}

        .chart-frame {{
            position: relative;
            height: 285px;
            width: 100%;
            min-width: 0;
        }}

        .chart-frame canvas {{
            display: block;
            width: 100% !important;
            height: 100% !important;
        }}

        .registry-card {{
            overflow: hidden;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th {{
            background: #21262d;
            color: var(--accent);
            text-align: left;
            padding: 14px 15px;
            font-size: 0.78rem;
            text-transform: uppercase;
        }}

        td {{
            padding: 15px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
            word-break: break-word;
        }}

        .ip-row {{
            cursor: pointer;
            transition: background 0.2s ease;
        }}

        .ip-row:hover {{
            background: var(--card-hover);
        }}

        .ip-address {{
            color: var(--accent);
            font-weight: 700;
        }}

        .subtle {{
            color: var(--muted);
            font-size: 0.88rem;
        }}

        .badge {{
            display: inline-block;
            background: #30363d;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8rem;
            max-width: 320px;
        }}

        .timeline-cell {{
            padding: 0;
            border: none;
        }}

        .timeline-wrapper {{
            display: none;
            background: #010409;
            padding: 20px;
            border-left: 3px solid var(--accent);
        }}

        .event-item {{
            margin-bottom: 15px;
            padding-bottom: 12px;
            border-bottom: 1px dashed var(--border);
            font-size: 0.9rem;
        }}

        .event-item:last-child {{
            margin-bottom: 0;
            border-bottom: none;
        }}

        .event-meta {{
            color: var(--muted);
            margin-bottom: 6px;
            display: block;
        }}

        .event-id {{
            display: inline-block;
            background: var(--success);
            color: white;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            margin-right: 8px;
        }}

        .event-id.cmd-in {{
            background: var(--accent);
        }}

        .event-msg {{
            color: #d1d5da;
            font-weight: 500;
        }}

        code {{
            display: block;
            background: #161b22;
            color: var(--cmd);
            padding: 10px;
            margin-top: 8px;
            border-radius: 4px;
            font-family: Consolas, "Courier New", monospace;
            border: 1px solid var(--border);
            white-space: pre-wrap;
            word-break: break-word;
        }}

        @media (max-width: 900px) {{
            body {{
                padding: 12px;
            }}

            .summary-row,
            .charts-row {{
                grid-template-columns: 1fr;
            }}

            th:nth-child(2),
            td:nth-child(2) {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Senior Design: Anomaly Detection Dashboard</h1>

        <div class="summary-row">
            <div class="summary-card">
                <span class="summary-label">Unique IPs</span>
                <span class="summary-value" id="unique-ip-count">0</span>
            </div>
            <div class="summary-card">
                <span class="summary-label">Total Events</span>
                <span class="summary-value" id="total-event-count">0</span>
            </div>
            <div class="summary-card">
                <span class="summary-label">Countries</span>
                <span class="summary-value" id="country-count">0</span>
            </div>
        </div>

        <div class="charts-row">
            <div class="chart-card">
                <h3>Top Attack Origins</h3>
                <div class="chart-frame">
                    <canvas id="countryChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>Event ID Distribution</h3>
                <div class="chart-frame">
                    <canvas id="eventChart"></canvas>
                </div>
            </div>
        </div>

        <div class="registry-card">
            <table>
                <thead>
                    <tr>
                        <th>Attacker IP & Location</th>
                        <th>ISP / Network</th>
                        <th>Activity Volume</th>
                        <th>Latest Event</th>
                    </tr>
                </thead>
                <tbody id="registry-body"></tbody>
            </table>
        </div>
    </div>

    <script>
        const ipData = {json.dumps(processed_ips)};
        const countryLabels = {json.dumps(list(country_stats.keys()))};
        const countryValues = {json.dumps(list(country_stats.values()))};
        const eventLabels = {json.dumps(list(event_stats.keys()))};
        const eventValues = {json.dumps(list(event_stats.values()))};

        const colors = ['#238636', '#1f6feb', '#d29922', '#f85149', '#8e15e9', '#3fb950', '#db6d28', '#a371f7'];

        document.getElementById('unique-ip-count').textContent = ipData.length;
        document.getElementById('total-event-count').textContent = ipData.reduce((sum, item) => sum + item.count, 0);
        document.getElementById('country-count').textContent = countryLabels.filter(country => country !== 'Unknown' && country !== 'Error').length;

        const chartOptions = {{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{
                legend: {{
                    position: 'right',
                    labels: {{ color: '#c9d1d9' }}
                }}
            }}
        }};

        new Chart(document.getElementById('countryChart'), {{
            type: 'pie',
            data: {{
                labels: countryLabels,
                datasets: [{{
                    data: countryValues,
                    backgroundColor: colors
                }}]
            }},
            options: chartOptions
        }});

        new Chart(document.getElementById('eventChart'), {{
            type: 'doughnut',
            data: {{
                labels: eventLabels,
                datasets: [{{
                    data: eventValues,
                    backgroundColor: colors
                }}]
            }},
            options: chartOptions
        }});

        function appendText(parent, tagName, text, className) {{
            const element = document.createElement(tagName);
            if (className) {{
                element.className = className;
            }}
            element.textContent = text;
            parent.appendChild(element);
            return element;
        }}

        function buildRegistry() {{
            const body = document.getElementById('registry-body');

            ipData.forEach((item, index) => {{
                const row = document.createElement('tr');
                row.className = 'ip-row';
                row.addEventListener('click', () => toggleTimeline(index));

                const ipCell = document.createElement('td');
                appendText(ipCell, 'div', item.ip, 'ip-address');
                appendText(ipCell, 'div', item.location, 'subtle');

                const ispCell = document.createElement('td');
                appendText(ispCell, 'span', item.isp, 'badge');

                const countCell = document.createElement('td');
                appendText(countCell, 'strong', item.count.toString(), null);
                countCell.appendChild(document.createTextNode(' events'));

                const latestCell = document.createElement('td');
                const latestEvent = item.timeline.length ? item.timeline[item.timeline.length - 1] : null;
                appendText(latestCell, 'small', latestEvent ? latestEvent.message || latestEvent.eventid : 'No events', null);

                row.appendChild(ipCell);
                row.appendChild(ispCell);
                row.appendChild(countCell);
                row.appendChild(latestCell);

                const detailRow = document.createElement('tr');
                const detailCell = document.createElement('td');
                detailCell.colSpan = 4;
                detailCell.className = 'timeline-cell';

                const timelineWrapper = document.createElement('div');
                timelineWrapper.id = `timeline-${{index}}`;
                timelineWrapper.className = 'timeline-wrapper';
                appendText(timelineWrapper, 'h3', 'Attack Sequence Timeline', null);

                item.timeline.forEach(event => {{
                    const eventItem = document.createElement('div');
                    eventItem.className = 'event-item';

                    appendText(eventItem, 'span', event.timestamp || 'Unknown time', 'event-meta');

                    const eventId = appendText(eventItem, 'span', event.eventid || 'unknown', 'event-id');
                    if ((event.eventid || '').toLowerCase().includes('input')) {{
                        eventId.classList.add('cmd-in');
                    }}

                    appendText(eventItem, 'span', event.message || '', 'event-msg');

                    if (event.input) {{
                        appendText(eventItem, 'code', `$ ${{event.input}}`, null);
                    }}

                    timelineWrapper.appendChild(eventItem);
                }});

                detailCell.appendChild(timelineWrapper);
                detailRow.appendChild(detailCell);

                body.appendChild(row);
                body.appendChild(detailRow);
            }});
        }}

        function toggleTimeline(index) {{
            const el = document.getElementById(`timeline-${{index}}`);
            el.style.display = el.style.display === 'block' ? 'none' : 'block';
        }}

        buildRegistry();
    </script>
</body>
</html>
"""


def generate_dashboard():
    if not os.path.exists(INPUT_FILE):
        print(f"[!] Error: {INPUT_FILE} not found.")
        return

    raw_data = load_json(INPUT_FILE, {})
    if not isinstance(raw_data, dict):
        print(f"[!] Error: {INPUT_FILE} must contain a JSON object keyed by IP address.")
        return

    geo_cache = load_json(GEO_CACHE_FILE, {})
    if not isinstance(geo_cache, dict):
        geo_cache = {}

    print(f"[*] Analyzing {len(raw_data)} unique IP profiles...")

    processed_ips = []
    all_event_ids = []
    countries = []

    for ip, timeline in raw_data.items():
        safe_ip = str(ip)
        print(f"    > Mapping {safe_ip}...")

        normalized_timeline = normalize_timeline(timeline)
        loc = get_location(safe_ip, geo_cache)
        country = loc.get("country") or "Unknown"

        countries.append(country)
        all_event_ids.extend(event["eventid"] for event in normalized_timeline)

        processed_ips.append(
            {
                "ip": safe_ip,
                "location": f"{loc.get('city') or 'Unknown'}, {country}",
                "isp": loc.get("isp") or "Unknown",
                "country": country,
                "count": len(normalized_timeline),
                "timeline": normalized_timeline,
            }
        )

    save_json(GEO_CACHE_FILE, geo_cache)

    processed_ips = sorted(processed_ips, key=lambda x: x["count"], reverse=True)
    country_stats = Counter(countries)
    event_stats = Counter(all_event_ids)

    html_content = build_html(processed_ips, country_stats, event_stats)

    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"\n[+] Dashboard complete: {os.path.abspath(OUTPUT_HTML)}")


if __name__ == "__main__":
    generate_dashboard()
