# Cybersecurity Incident Risk Analysis

This comprehensive project analyzes cybersecurity incident logs to identify threat patterns, calculate risk scores, and visualize attack behavior. It simulates how a Security Operations Center (SOC) monitors and evaluates potential threats using Python, SQL, and Power BI.

## 🎯 Project Purpose

The goal of this project is to perform end-to-end cybersecurity analytics including:
- Security incident analytics and trend analysis
- Advanced threat detection and anomaly identification
- Multi-dimensional risk scoring with ensemble methods
- Log monitoring and correlation analysis
- Geographic threat pattern recognition
- Actionable security intelligence for SOC teams

## 📊 Datasets Overview

### **incidents.csv** (5,000 records)
Security incident logs with attack patterns, severity levels, and geographic data.

### **logins.csv** (3,000 records)
User authentication attempts with success/failure tracking and IP correlation.

## 🛠 Technology Stack

- **Python**: Pandas, NumPy, Scikit-learn, Matplotlib, Seaborn, Plotly
- **SQL**: SQLite with comprehensive analytics queries
- **Power BI**: Interactive dashboard for security monitoring
- **Machine Learning**: Isolation Forest, statistical anomaly detection
- **Risk Scoring**: Multiple algorithms (basic, advanced, temporal, ensemble)

## 🚀 Quick Start

### Prerequisites
```bash
# Install Python dependencies
pip install -r requirements.txt

# Required libraries
pandas>=1.5.0
scikit-learn>=1.2.0
matplotlib>=3.6.0
plotly>=5.10.0
jupyter>=1.0.0
```

### Run Analysis Pipeline
```bash
# 1. Execute data preprocessing
python scripts/preprocess.py

# 2. Run comprehensive analysis
jupyter notebook notebooks/incident_analysis.ipynb

# 3. Build risk profiles
python scripts/risk_scoring.py
```

## 📁 Project Structure

```
cybersecurity-incident-risk-analysis/
│
├── data/
│   ├── incidents.csv              # Raw incident data
│   └── logins.csv                 # Raw login data
│
├── scripts/
│   ├── preprocess.py              # Data cleaning & ETL pipeline
│   └── risk_scoring.py            # Risk calculation algorithms
│
├── notebooks/
│   └── incident_analysis.ipynb    # Comprehensive data analysis
│
├── sql/
│   ├── create_tables.sql          # Database schema
│   └── incident_queries.sql       # Analytics queries
│
├── dashboard/
│   ├── README.md                  # Power BI setup guide
│   ├── data/                      # Processed datasets for Power BI
│   │   ├── incidents_cleaned.csv
│   │   ├── logins_cleaned.csv
│   │   ├── security_events_merged.csv
│   │   ├── top_risk_profiles.csv
│   │   └── data_dictionary.csv
│   └── reports/                   # Power BI files (.pbix)
│
├── requirements.txt               # Python dependencies
└── README.md                      # This file
```

## 📈 Key Features

### Risk Scoring Engine
- **Basic Risk**: frequency × severity_weight
- **Advanced Risk**: Multi-factor scoring (frequency, severity, success rate, persistence, diversity)
- **Temporal Risk**: Time-decay weighted scoring
- **Ensemble Risk**: Combined scoring with confidence weights
- **Anomaly Detection**: Isolation Forest + statistical methods

### Analytics Capabilities
- Incident trend analysis (daily, weekly, monthly patterns)
- Attack frequency analysis by event type and location
- Severity distribution and critical incident tracking
- Top attacker IP identification and profiling
- Geographic threat mapping
- Login behavior anomaly detection
- Correlation analysis between incidents and logins

### Data Processing
- Automated data validation and cleaning
- IP address validation and normalization
- Temporal feature engineering
- Dataset correlation and merging
- Missing value handling
- Outlier detection and treatment

## 📊 Analysis Highlights

### Threat Intelligence
- **Risk Classification**: Automated Low/Medium/High/Critical scoring
- **Anomaly Detection**: Identifies unusual attack patterns
- **Geographic Analysis**: Location-based threat assessment
- **Behavioral Patterns**: Time-based attack pattern recognition

### Key Metrics
- Incident frequency trends and seasonality
- Attack success rates by category
- Top attacking IPs with risk profiles
- Critical incident hotspots
- Login failure correlation with security events

## 🎯 Power BI Dashboard

Pre-processed datasets are automatically exported for Power BI consumption:

1. **Incidents Analysis**: Event types, severity trends, temporal patterns
2. **Risk Monitoring**: Risk score distributions, top threats, anomaly alerts
3. **Geographic Intelligence**: Location-based threat mapping
4. **Login Security**: Authentication patterns, brute force detection
5. **Executive Summary**: KPIs, trends, and actionable insights

### Dashboard Features
- Interactive risk heatmaps
- Real-time threat monitoring
- Drill-down incident analysis
- Automated alerting for critical risks
- Trend forecasting and predictions

## 📋 Usage Examples

### Basic Data Exploration
```python
from scripts.preprocess import DataPreprocessor

# Load and clean data
preprocessor = DataPreprocessor()
incidents_df = preprocessor.load_incidents_data("data/incidents.csv")
logins_df = preprocessor.load_logins_data("data/logins.csv")

# Get quality report
quality_report = preprocessor.get_data_quality_report()
```

### Risk Analysis
```python
from scripts.risk_scoring import RiskScorer

# Calculate comprehensive risk profiles
risk_scorer = RiskScorer()
risk_profile = risk_scorer.calculate_combined_risk_profile(incidents_df)

# Get top threats
top_threats = risk_profile.head(10)
```

### SQL Analytics
```sql
-- Execute queries from sql/incident_queries.sql
-- Examples: daily trends, top attackers, risk scoring
SELECT * FROM incidents WHERE severity = 'Critical';
```

## 🔍 Advanced Analytics

- **Time Series Forecasting**: Predict incident volumes
- **Clustering Analysis**: Group similar attack patterns
- **Network Analysis**: IP relationship mapping
- **Predictive Modeling**: Risk score prediction
- **Anomaly Prediction**: Future threat likelihood

## 📊 Results Summary

The analysis typically reveals:
- **500+ unique attacker IPs** with risk profiles
- **Peak attack hours** (typically business hours)
- **Top attack vectors** (Failed Login, Phishing, Malware)
- **Geographic hotspots** (China, Russia, Unknown locations)
- **Risk distribution**: ~20% High/Critical threats requiring immediate attention

## 🤝 Contributing

This is a portfolio project demonstrating cybersecurity analytics capabilities. For enhancements:
1. Add new risk scoring algorithms
2. Implement additional ML models
3. Create custom Power BI visualizations
4. Add predictive analytics features

## 📄 License

Portfolio project - feel free to use as reference for cybersecurity analytics implementations.

---

**Ready to analyze threats?** Start with `python scripts/preprocess.py` and explore `notebooks/incident_analysis.ipynb` for comprehensive insights.
