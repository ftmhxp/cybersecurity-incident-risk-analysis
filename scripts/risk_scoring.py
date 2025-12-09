"""
Cybersecurity Risk Scoring Module

This module provides comprehensive risk scoring algorithms for security incidents,
including basic formulas, advanced models, and anomaly detection.
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional, Union
from datetime import datetime, timedelta
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from scipy import stats
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RiskScorer:
    """Main class for calculating various risk scores."""

    def __init__(self):
        self.severity_weights = {
            'Low': 1,
            'Medium': 2,
            'High': 3,
            'Critical': 4
        }
        self.status_weights = {
            'Successful': 1.0,
            'Failed': 0.3,
            'Blocked': 0.1,
            'Allowed': 0.8
        }

    def calculate_basic_risk_score(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculate basic risk score: severity_weight × incident_frequency

        Args:
            df: DataFrame with incidents data

        Returns:
            DataFrame with risk scores added
        """
        df = df.copy()

        # Calculate severity scores
        df['severity_weight'] = df['severity'].map(self.severity_weights)

        # Calculate risk scores by IP
        ip_risk = df.groupby('source_ip').agg({
            'event_id': 'count',
            'severity_weight': 'mean',
            'status': lambda x: (x == 'Successful').mean(),
            'timestamp': ['min', 'max', lambda x: x.nunique()]
        }).round(3)

        # Flatten column names
        ip_risk.columns = ['incident_count', 'avg_severity', 'success_rate',
                          'first_seen', 'last_seen', 'active_days']

        # Calculate basic risk score
        ip_risk['basic_risk_score'] = (
            ip_risk['incident_count'] * ip_risk['avg_severity']
        ).round(2)

        # Classify risk levels
        ip_risk['risk_level'] = pd.cut(
            ip_risk['basic_risk_score'],
            bins=[0, 5, 15, 30, float('inf')],
            labels=['Low', 'Medium', 'High', 'Critical']
        )

        return ip_risk.reset_index()

    def calculate_advanced_risk_score(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculate advanced risk score with multiple factors:
        - Frequency (30%)
        - Severity (25%)
        - Success Rate (20%)
        - Persistence (15%)
        - Diversity (10%)

        Args:
            df: DataFrame with incidents data

        Returns:
            DataFrame with advanced risk scores
        """
        df = df.copy()

        # Group by IP and calculate metrics
        ip_stats = df.groupby('source_ip').agg({
            'event_id': 'count',
            'severity': lambda x: x.map(self.severity_weights).mean(),
            'status': lambda x: (x == 'Successful').mean(),
            'event_type': 'nunique',
            'timestamp': lambda x: (x.max() - x.min()).days if len(x) > 1 else 0,
            'location': 'nunique',
            'destination_device': 'nunique'
        }).round(3)

        ip_stats.columns = ['frequency', 'avg_severity', 'success_rate',
                           'event_diversity', 'persistence_days', 'location_diversity',
                           'target_diversity']

        # Normalize metrics to 0-1 scale
        scaler = StandardScaler()
        metrics_cols = ['frequency', 'avg_severity', 'success_rate',
                       'event_diversity', 'persistence_days', 'location_diversity',
                       'target_diversity']

        ip_stats_scaled = pd.DataFrame(
            scaler.fit_transform(ip_stats[metrics_cols]),
            columns=metrics_cols,
            index=ip_stats.index
        )

        # Apply weights and calculate composite score
        weights = {
            'frequency': 0.30,      # How often they attack
            'avg_severity': 0.25,   # Severity of attacks
            'success_rate': 0.20,   # Success rate (higher = more dangerous)
            'event_diversity': 0.10, # Variety of attack types
            'persistence_days': 0.15 # How long they've been active
        }

        ip_stats['advanced_risk_score'] = 0
        for metric, weight in weights.items():
            if metric in ip_stats_scaled.columns:
                # Transform to 0-1 scale and weight
                normalized = (ip_stats_scaled[metric] - ip_stats_scaled[metric].min()) / \
                           (ip_stats_scaled[metric].max() - ip_stats_scaled[metric].min())
                ip_stats['advanced_risk_score'] += normalized * weight * 100

        ip_stats['advanced_risk_score'] = ip_stats['advanced_risk_score'].round(2)

        # Classify risk levels
        ip_stats['advanced_risk_level'] = pd.cut(
            ip_stats['advanced_risk_score'],
            bins=[0, 25, 50, 75, float('inf')],
            labels=['Low', 'Medium', 'High', 'Critical']
        )

        return ip_stats.reset_index()

    def calculate_temporal_risk_score(self, df: pd.DataFrame,
                                     window_days: int = 7) -> pd.DataFrame:
        """
        Calculate risk scores with temporal decay (recent incidents weigh more).

        Args:
            df: DataFrame with incidents data
            window_days: Number of days to look back

        Returns:
            DataFrame with temporal risk scores
        """
        df = df.copy()
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        max_date = df['timestamp'].max()

        # Calculate recency weight (exponential decay)
        df['days_since'] = (max_date - df['timestamp']).dt.days
        df['recency_weight'] = np.exp(-df['days_since'] / window_days)

        # Calculate weighted severity
        df['weighted_severity'] = (
            df['severity'].map(self.severity_weights) * df['recency_weight']
        )

        # Group by IP and calculate temporal metrics
        temporal_risk = df.groupby('source_ip').agg({
            'event_id': 'count',
            'weighted_severity': 'sum',
            'recency_weight': 'sum',
            'days_since': 'min',  # Most recent incident
            'event_type': 'nunique'
        }).round(3)

        temporal_risk.columns = ['total_incidents', 'weighted_severity_sum',
                               'total_weight', 'most_recent_days', 'event_diversity']

        # Calculate temporal risk score
        temporal_risk['temporal_risk_score'] = (
            temporal_risk['weighted_severity_sum'] /
            temporal_risk['total_weight'].replace(0, 1) * 10
        ).round(2)

        # Adjust for recency bonus
        temporal_risk['recency_bonus'] = np.exp(-temporal_risk['most_recent_days'] / 30)
        temporal_risk['temporal_risk_score'] *= (1 + temporal_risk['recency_bonus'])

        # Classify risk levels
        temporal_risk['temporal_risk_level'] = pd.cut(
            temporal_risk['temporal_risk_score'],
            bins=[0, 10, 25, 50, float('inf')],
            labels=['Low', 'Medium', 'High', 'Critical']
        )

        return temporal_risk.reset_index()

    def calculate_anomaly_scores(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculate anomaly scores using isolation forest and statistical methods.

        Args:
            df: DataFrame with incidents data

        Returns:
            DataFrame with anomaly scores
        """
        df = df.copy()

        # Prepare features for anomaly detection
        features_df = df.groupby('source_ip').agg({
            'event_id': 'count',
            'severity': lambda x: x.map(self.severity_weights).mean(),
            'status': lambda x: (x == 'Successful').mean(),
            'event_type': 'nunique',
            'timestamp': lambda x: x.dt.hour.mean() if len(x) > 0 else 12,
            'location': lambda x: len(x.unique()) if x.notna().any() else 1
        }).round(3)

        features_df.columns = ['frequency', 'avg_severity', 'success_rate',
                             'event_diversity', 'avg_hour', 'location_count']

        # Isolation Forest for unsupervised anomaly detection
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        features_df['isolation_score'] = -iso_forest.fit_predict(features_df)

        # Statistical anomaly detection (Z-score method)
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features_df)
        z_scores = np.abs(stats.zscore(scaled_features))

        features_df['z_score_max'] = np.max(z_scores, axis=1)
        features_df['z_score_avg'] = np.mean(z_scores, axis=1)

        # Composite anomaly score
        features_df['anomaly_score'] = (
            features_df['isolation_score'] * 0.6 +
            features_df['z_score_max'] * 0.4
        ).round(3)

        # Classify anomaly levels
        features_df['anomaly_level'] = pd.cut(
            features_df['anomaly_score'],
            bins=[-float('inf'), 0.5, 1.0, 1.5, float('inf')],
            labels=['Normal', 'Suspicious', 'Anomalous', 'Critical_Anomaly']
        )

        return features_df.reset_index()

    def calculate_geographic_risk_score(self, df: pd.DataFrame,
                                       high_risk_countries: List[str] = None) -> pd.DataFrame:
        """
        Calculate risk scores with geographic factors.

        Args:
            df: DataFrame with incidents data
            high_risk_countries: List of high-risk countries

        Returns:
            DataFrame with geographic risk scores
        """
        if high_risk_countries is None:
            high_risk_countries = ['Unknown', 'Russia', 'China', 'North Korea']

        df = df.copy()

        # Geographic risk factors
        df['country_risk'] = df['location'].apply(
            lambda x: 3 if x in high_risk_countries else 1
        )

        # Calculate geographic risk scores
        geo_risk = df.groupby('source_ip').agg({
            'event_id': 'count',
            'country_risk': 'mean',
            'location': lambda x: len(x.unique()),
            'severity': lambda x: x.map(self.severity_weights).mean()
        }).round(3)

        geo_risk.columns = ['frequency', 'avg_country_risk', 'location_diversity', 'avg_severity']

        # Composite geographic risk score
        geo_risk['geo_risk_score'] = (
            geo_risk['frequency'] *
            geo_risk['avg_severity'] *
            geo_risk['avg_country_risk'] *
            np.log1p(geo_risk['location_diversity'])
        ).round(2)

        # Classify geographic risk levels
        geo_risk['geo_risk_level'] = pd.cut(
            geo_risk['geo_risk_score'],
            bins=[0, 10, 30, 70, float('inf')],
            labels=['Low', 'Medium', 'High', 'Critical']
        )

        return geo_risk.reset_index()

    def calculate_combined_risk_profile(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculate comprehensive risk profile combining all scoring methods.

        Args:
            df: DataFrame with incidents data

        Returns:
            DataFrame with complete risk profile
        """
        logger.info("Calculating comprehensive risk profile...")

        # Calculate all risk scores
        basic_risk = self.calculate_basic_risk_score(df)
        advanced_risk = self.calculate_advanced_risk_score(df)
        temporal_risk = self.calculate_temporal_risk_score(df)
        anomaly_scores = self.calculate_anomaly_scores(df)
        geo_risk = self.calculate_geographic_risk_score(df)

        # Merge all risk scores
        risk_profile = basic_risk[['source_ip', 'basic_risk_score', 'risk_level']]

        # Join other risk metrics
        risk_metrics = [
            advanced_risk[['source_ip', 'advanced_risk_score', 'advanced_risk_level']],
            temporal_risk[['source_ip', 'temporal_risk_score', 'temporal_risk_level']],
            anomaly_scores[['source_ip', 'anomaly_score', 'anomaly_level']],
            geo_risk[['source_ip', 'geo_risk_score', 'geo_risk_level']]
        ]

        for metric_df in risk_metrics:
            risk_profile = risk_profile.merge(metric_df, on='source_ip', how='left')

        # Calculate ensemble risk score (weighted average)
        score_columns = ['basic_risk_score', 'advanced_risk_score',
                        'temporal_risk_score', 'anomaly_score', 'geo_risk_score']

        weights = [0.2, 0.3, 0.25, 0.15, 0.1]  # Weights for each scoring method

        risk_profile['ensemble_risk_score'] = 0
        for col, weight in zip(score_columns, weights):
            if col in risk_profile.columns:
                # Normalize each score to 0-1 scale within its column
                normalized = (risk_profile[col] - risk_profile[col].min()) / \
                           (risk_profile[col].max() - risk_profile[col].min()).replace(0, 1)
                risk_profile['ensemble_risk_score'] += normalized * weight * 100

        risk_profile['ensemble_risk_score'] = risk_profile['ensemble_risk_score'].round(2)

        # Final risk classification
        risk_profile['final_risk_level'] = pd.cut(
            risk_profile['ensemble_risk_score'],
            bins=[0, 30, 55, 80, float('inf')],
            labels=['Low', 'Medium', 'High', 'Critical']
        )

        # Add risk trend indicator (simplified)
        risk_profile['risk_trend'] = 'Stable'  # In real implementation, compare with historical data

        # Sort by ensemble risk score
        risk_profile = risk_profile.sort_values('ensemble_risk_score', ascending=False)

        logger.info(f"Calculated risk profiles for {len(risk_profile)} IPs")
        return risk_profile

    def get_risk_summary(self, risk_profile: pd.DataFrame) -> Dict:
        """
        Generate risk summary statistics.

        Args:
            risk_profile: DataFrame with risk profiles

        Returns:
            Dictionary with risk summary statistics
        """
        summary = {
            'total_ips_analyzed': len(risk_profile),
            'high_risk_ips': len(risk_profile[risk_profile['final_risk_level'] == 'High']),
            'critical_risk_ips': len(risk_profile[risk_profile['final_risk_level'] == 'Critical']),
            'avg_ensemble_score': risk_profile['ensemble_risk_score'].mean().round(2),
            'max_risk_score': risk_profile['ensemble_risk_score'].max(),
            'risk_distribution': risk_profile['final_risk_level'].value_counts().to_dict()
        }

        return summary


def main():
    """Example usage of risk scoring module."""
    from preprocess import DataPreprocessor

    # Load and preprocess data
    preprocessor = DataPreprocessor()
    incidents_df = preprocessor.load_incidents_data("data/incidents.csv")

    # Initialize risk scorer
    risk_scorer = RiskScorer()

    # Calculate comprehensive risk profile
    risk_profile = risk_scorer.calculate_combined_risk_profile(incidents_df)

    # Get risk summary
    summary = risk_scorer.get_risk_summary(risk_profile)

    print("Risk Analysis Summary:")
    for key, value in summary.items():
        print(f"{key}: {value}")

    # Export top risk IPs
    top_risks = risk_profile.head(20)
    top_risks.to_csv("dashboard/data/top_risk_profiles.csv", index=False)
    print("Top 20 risk profiles exported to dashboard/data/top_risk_profiles.csv")


if __name__ == "__main__":
    main()
