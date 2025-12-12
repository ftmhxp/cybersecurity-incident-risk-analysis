# Cybersecurity Incident Risk Analysis Dashboard

This directory contains data preparation files and documentation for Power BI dashboard development.

## Dashboard Overview

The Power BI dashboard will visualize cybersecurity incident data, risk scores, and threat patterns to support security operations center (SOC) decision-making.

## Directory Structure

```
dashboard/
├── data/                 # Processed datasets for Power BI
│   ├── incidents_cleaned.csv
│   ├── logins_cleaned.csv
│   ├── security_events_merged.csv
│   └── top_risk_profiles.csv
├── reports/              # Power BI report files (.pbix)
└── README.md            # This file
```

## Data Sources

### 1. incidents_cleaned.csv
**Purpose**: Primary security incident data with enhanced features
**Record Count**: ~5,000 incidents
**Key Fields**:
- `event_id`: Unique incident identifier
- `timestamp`: Incident timestamp (datetime)
- `event_type`: Attack type (Failed Login, Phishing, Malware, etc.)
- `severity`: Incident severity (Low, Medium, High, Critical)
- `severity_score`: Numeric severity (1-4)
- `source_ip`: Attacking IP address
- `destination_device`: Target device identifier
- `status`: Incident outcome (Successful, Failed, Blocked, Allowed)
- `location`: Geographic location
- `hour`: Hour of incident (0-23)
- `day_of_week`: Day name
- `is_weekend`: Boolean weekend flag

### 2. logins_cleaned.csv
**Purpose**: Authentication attempt data
**Record Count**: ~3,000 login attempts
**Key Fields**:
- `login_id`: Unique login identifier
- `user_id`: User identifier
- `login_time`: Login timestamp (datetime)
- `success`: Login outcome (True/False)
- `ip_address`: Login IP address
- `hour`: Hour of login (0-23)
- `day_of_week`: Day name
- `is_weekend`: Boolean weekend flag

### 3. security_events_merged.csv
**Purpose**: Correlated incidents and logins by IP and time
**Record Count**: Variable (correlated events only)
**Key Fields**:
- All incident fields (prefixed with `incident_`)
- All login fields (prefixed with `login_`)
- `source_ip`: Common IP address
- `combined_risk_score`: Risk score combining incident severity and login failures

### 4. top_risk_profiles.csv
**Purpose**: Risk-scored attacker profiles
**Record Count**: ~500 unique IPs
**Key Fields**:
- `source_ip`: Attacking IP address
- `ensemble_risk_score`: Combined risk score (0-100)
- `final_risk_level`: Risk classification (Low, Medium, High, Critical)
- `basic_risk_score`: Simple frequency × severity score
- `advanced_risk_score`: Multi-factor risk score
- `temporal_risk_score`: Time-weighted risk score
- `anomaly_score`: Anomaly detection score
- `geo_risk_score`: Geographic risk score

## Recommended Dashboard Pages

### 1. Executive Summary
- **KPIs**: Total incidents, success rate, critical incidents, active threats
- **Risk Overview**: Risk level distribution, top threats
- **Trends**: Daily/weekly incident trends

### 2. Incident Analysis
- **Event Types**: Distribution and success rates
- **Severity Analysis**: Critical incident trends, severity by location
- **Temporal Patterns**: Hourly/daily/weekly patterns

### 3. Threat Intelligence
- **Top Attackers**: Risk-ranked IP addresses
- **Geographic Threats**: Location-based analysis
- **Attack Patterns**: Event type correlations

### 4. Risk Monitoring
- **Risk Scores**: Ensemble risk distribution
- **Anomaly Detection**: Unusual behavior patterns
- **Trend Analysis**: Risk score changes over time

### 5. Login Security
- **Authentication Trends**: Success/failure rates
- **Brute Force Detection**: Failed login patterns
- **User Behavior**: Anomalous login activity

## Key Visualizations

### Charts & Graphs
1. **Line Chart**: Daily incident volume with severity overlay
2. **Bar Chart**: Event type distribution and success rates
3. **Pie Chart**: Risk level distribution
4. **Heat Map**: Hourly activity patterns
5. **Scatter Plot**: Risk score vs frequency analysis
6. **Geographic Map**: Incident density by location

### KPIs & Cards
1. Total Incidents (current period)
2. Critical Incident Count
3. Average Risk Score
4. Attack Success Rate
5. Unique Attacker IPs
6. Peak Hour Activity

### Tables & Matrices
1. **Top Risk IPs**: Sortable table with all risk metrics
2. **Incident Details**: Drill-down incident table
3. **Location Summary**: Geographic risk summary
4. **Trend Analysis**: Period-over-period comparisons

## Power BI Setup Instructions

### 1. Data Import
1. Open Power BI Desktop
2. Click "Get Data" → "Text/CSV"
3. Import all four CSV files from the `data/` directory
4. Ensure date columns are properly formatted as DateTime

### 2. Data Relationships
Create relationships between tables:
- `incidents_cleaned` ↔ `logins_cleaned` (on IP address)
- `incidents_cleaned` ↔ `top_risk_profiles` (on source_ip)
- `security_events_merged` (contains correlated data)

### 3. Calculated Columns & Measures
Add these DAX measures for enhanced analysis:

```dax
// Risk Score Categories
Risk Category = SWITCH(
    TRUE(),
    'top_risk_profiles'[ensemble_risk_score] >= 80, "Critical",
    'top_risk_profiles'[ensemble_risk_score] >= 55, "High",
    'top_risk_profiles'[ensemble_risk_score] >= 30, "Medium",
    "Low"
)

// Success Rate Percentage
Success Rate % = DIVIDE(
    COUNTROWS(FILTER('incidents_cleaned', 'incidents_cleaned'[status] = "Successful")),
    COUNTROWS('incidents_cleaned')
)

// Daily Incident Trend
Daily Incidents = CALCULATE(
    COUNTROWS('incidents_cleaned'),
    DATESYTD('incidents_cleaned'[timestamp])
)
```

### 4. Custom Visualizations
- Use conditional formatting for risk levels (red for Critical, etc.)
- Add data slicers for date ranges, locations, and event types
- Implement drill-through pages for detailed IP analysis

## Automated Alerts Setup

Configure alerts for:
- New critical-risk IPs (ensemble_risk_score > 80)
- Incident spikes (>200% of daily average)
- High-severity incident clusters
- Anomalous behavior detection

## Dashboard Refresh

### Manual Refresh
1. Open Power BI Desktop
2. Click "Refresh" to update with new data
3. Republish to Power BI Service

### Scheduled Refresh (Power BI Service)
1. Publish report to Power BI Service
2. Configure gateway for data source access
3. Set up scheduled refresh (hourly/daily)
4. Configure data alerts

## Advanced Analytics

### Custom Calculations
- **Risk Velocity**: Rate of risk score increase
- **Threat Persistence**: Days since first/last incident
- **Attack Diversity**: Number of unique event types per IP
- **Geographic Risk**: Location-based risk multipliers

### Predictive Analytics
- **Trend Forecasting**: Time series prediction for incident volume
- **Risk Prediction**: Machine learning-based risk scoring
- **Anomaly Prediction**: Future anomaly likelihood

## Data Dictionary

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| event_id | Integer | Unique incident identifier | 12345 |
| timestamp | DateTime | Incident occurrence time | 2025-01-15 14:30:00 |
| event_type | String | Attack category | "Phishing Attempt" |
| severity | String | Impact level | "High" |
| severity_score | Integer | Numeric severity (1-4) | 3 |
| source_ip | String | Attacker IP address | "192.168.1.100" |
| status | String | Incident outcome | "Blocked" |
| location | String | Geographic origin | "China" |
| ensemble_risk_score | Float | Combined risk score | 75.5 |
| final_risk_level | String | Risk classification | "High" |

## Success Metrics

- **Dashboard Usage**: Regular access by security team
- **Response Time**: Time to investigate alerts
- **False Positive Rate**: Accuracy of risk scoring
- **Threat Detection**: Critical threats identified and mitigated
- **Incident Reduction**: Trend in incident volume over time

## Support

For questions about dashboard development or data interpretation:
1. Refer to the analysis notebook (`notebooks/incident_analysis.ipynb`)
2. Check the SQL queries (`sql/incident_queries.sql`)
3. Review the preprocessing scripts (`scripts/`)

## Update Process

1. Run data preprocessing scripts to generate new datasets
2. Execute analysis notebook for updated insights
3. Refresh Power BI data sources
4. Review and update dashboard visualizations
5. Republish updated report

---

**Note**: This dashboard provides actionable intelligence for cybersecurity operations. Regular updates and validation against real incidents are recommended for optimal effectiveness.
