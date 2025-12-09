"""
Cybersecurity Incident Data Preprocessing Script

This module provides ETL functions for cleaning, validating, and transforming
security incident and login data for risk analysis.
"""

import pandas as pd
import numpy as np
import logging
from typing import Dict, List, Tuple, Optional, Union
from datetime import datetime, timedelta
import ipaddress
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DataPreprocessor:
    """Main class for preprocessing cybersecurity data."""

    def __init__(self):
        self.incidents_df = None
        self.logins_df = None
        self.merged_df = None

    def load_incidents_data(self, file_path: str) -> pd.DataFrame:
        """
        Load and validate incidents data.

        Args:
            file_path: Path to incidents CSV file

        Returns:
            Cleaned incidents DataFrame
        """
        try:
            logger.info(f"Loading incidents data from {file_path}")
            df = pd.read_csv(file_path, parse_dates=['timestamp'])

            # Validate required columns
            required_cols = ['event_id', 'timestamp', 'event_type', 'severity',
                           'source_ip', 'destination_device', 'status', 'location']
            self._validate_columns(df, required_cols, 'incidents')

            # Data type conversions and cleaning
            df = self._clean_incidents_data(df)

            # Validate data integrity
            self._validate_incidents_data(df)

            self.incidents_df = df
            logger.info(f"Successfully loaded {len(df)} incident records")
            return df

        except Exception as e:
            logger.error(f"Failed to load incidents data: {str(e)}")
            raise

    def load_logins_data(self, file_path: str) -> pd.DataFrame:
        """
        Load and validate logins data.

        Args:
            file_path: Path to logins CSV file

        Returns:
            Cleaned logins DataFrame
        """
        try:
            logger.info(f"Loading logins data from {file_path}")
            df = pd.read_csv(file_path, parse_dates=['login_time'])

            # Validate required columns
            required_cols = ['login_id', 'user_id', 'login_time', 'success', 'ip_address']
            self._validate_columns(df, required_cols, 'logins')

            # Data type conversions and cleaning
            df = self._clean_logins_data(df)

            # Validate data integrity
            self._validate_logins_data(df)

            self.logins_df = df
            logger.info(f"Successfully loaded {len(df)} login records")
            return df

        except Exception as e:
            logger.error(f"Failed to load logins data: {str(e)}")
            raise

    def merge_datasets(self, time_window_minutes: int = 60) -> pd.DataFrame:
        """
        Merge incidents and logins data based on IP address and time proximity.

        Args:
            time_window_minutes: Time window for correlating events

        Returns:
            Merged DataFrame with correlated events
        """
        if self.incidents_df is None or self.logins_df is None:
            raise ValueError("Both incidents and logins data must be loaded before merging")

        try:
            logger.info("Merging incidents and logins data")

            # Rename columns for clarity in merged dataset
            incidents_renamed = self.incidents_df.copy()
            incidents_renamed.columns = [f"incident_{col}" if col != 'source_ip' else col
                                       for col in incidents_renamed.columns]

            logins_renamed = self.logins_df.copy()
            logins_renamed.columns = [f"login_{col}" if col not in ['ip_address', 'login_time'] else col
                                    for col in logins_renamed.columns]
            logins_renamed = logins_renamed.rename(columns={'ip_address': 'source_ip'})

            # Perform cross join within time windows (simplified approach)
            # In production, you'd want a more efficient temporal join
            merged = []

            for _, incident in incidents_renamed.iterrows():
                # Find logins from same IP within time window
                time_mask = (
                    (logins_renamed['login_time'] >= incident['incident_timestamp'] - timedelta(minutes=time_window_minutes)) &
                    (logins_renamed['login_time'] <= incident['incident_timestamp'] + timedelta(minutes=time_window_minutes))
                )
                ip_mask = (logins_renamed['source_ip'] == incident['source_ip'])

                related_logins = logins_renamed[time_mask & ip_mask]

                if len(related_logins) > 0:
                    # Merge each incident with its related logins
                    for _, login in related_logins.iterrows():
                        merged_row = pd.concat([incident, login])
                        merged.append(merged_row)
                else:
                    # Include incidents with no matching logins
                    merged_row = pd.concat([incident, pd.Series(dtype=object)])
                    merged.append(merged_row)

            if merged:
                result_df = pd.DataFrame(merged)
                result_df = result_df.drop_duplicates()
            else:
                # If no correlations found, return incidents only
                result_df = incidents_renamed.copy()

            # Add derived features
            result_df = self._add_derived_features(result_df)

            self.merged_df = result_df
            logger.info(f"Successfully merged datasets: {len(result_df)} correlated records")
            return result_df

        except Exception as e:
            logger.error(f"Failed to merge datasets: {str(e)}")
            raise

    def _clean_incidents_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and transform incidents data."""
        df = df.copy()

        # Standardize severity values
        severity_mapping = {
            'low': 'Low', 'medium': 'Medium', 'high': 'High', 'critical': 'Critical'
        }
        df['severity'] = df['severity'].str.lower().map(severity_mapping).fillna(df['severity'])

        # Clean IP addresses
        df['source_ip'] = df['source_ip'].apply(self._validate_and_clean_ip)

        # Standardize location names
        df['location'] = df['location'].str.strip().str.title()

        # Extract temporal features
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.day_name()
        df['month'] = df['timestamp'].dt.month
        df['is_weekend'] = df['timestamp'].dt.weekday >= 5

        # Create severity score
        severity_scores = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        df['severity_score'] = df['severity'].map(severity_scores)

        return df

    def _clean_logins_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and transform logins data."""
        df = df.copy()

        # Standardize success values
        df['success'] = df['success'].map({'Yes': True, 'No': False, 'yes': True, 'no': False})

        # Clean IP addresses
        df['ip_address'] = df['ip_address'].apply(self._validate_and_clean_ip)

        # Extract temporal features
        df['hour'] = df['login_time'].dt.hour
        df['day_of_week'] = df['login_time'].dt.day_name()
        df['month'] = df['login_time'].dt.month
        df['is_weekend'] = df['login_time'].dt.weekday >= 5

        return df

    def _validate_columns(self, df: pd.DataFrame, required_cols: List[str], dataset_name: str):
        """Validate that required columns exist."""
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            raise ValueError(f"Missing required columns in {dataset_name} data: {missing_cols}")

    def _validate_incidents_data(self, df: pd.DataFrame):
        """Validate incidents data integrity."""
        # Check for valid severity values
        valid_severities = ['Low', 'Medium', 'High', 'Critical']
        invalid_severities = df[~df['severity'].isin(valid_severities)]['severity'].unique()
        if len(invalid_severities) > 0:
            logger.warning(f"Found invalid severity values: {invalid_severities}")

        # Check for valid status values
        valid_statuses = ['Successful', 'Failed', 'Blocked', 'Allowed']
        invalid_statuses = df[~df['status'].isin(valid_statuses)]['status'].unique()
        if len(invalid_statuses) > 0:
            logger.warning(f"Found invalid status values: {invalid_statuses}")

        # Check timestamp range
        if df['timestamp'].min() > pd.Timestamp.now() or df['timestamp'].max() < pd.Timestamp('2020-01-01'):
            logger.warning("Timestamp range appears unusual")

    def _validate_logins_data(self, df: pd.DataFrame):
        """Validate logins data integrity."""
        # Check success rate (should not be 100% or 0%)
        success_rate = df['success'].mean()
        if success_rate > 0.95 or success_rate < 0.05:
            logger.warning(".2%")

    def _validate_and_clean_ip(self, ip_str: str) -> str:
        """Validate and clean IP address strings."""
        if pd.isna(ip_str):
            return None

        ip_str = str(ip_str).strip()

        try:
            # Try to parse as IPv4 or IPv6
            ipaddress.ip_address(ip_str)
            return ip_str
        except ValueError:
            # If parsing fails, try to clean common issues
            # Remove extra spaces, handle malformed IPs
            cleaned = re.sub(r'[^\d.]', '', ip_str)
            try:
                ipaddress.ip_address(cleaned)
                return cleaned
            except ValueError:
                logger.warning(f"Invalid IP address: {ip_str}")
                return None

    def _add_derived_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add derived features for analysis."""
        df = df.copy()

        # Risk score combining incident severity and login failures
        if 'incident_severity_score' in df.columns and 'login_success' in df.columns:
            df['combined_risk_score'] = (
                df['incident_severity_score'].fillna(0) +
                (1 - df['login_success'].astype(int)).fillna(0) * 2
            )

        # Time-based features
        if 'incident_timestamp' in df.columns:
            df['incident_hour'] = df['incident_timestamp'].dt.hour
            df['incident_is_business_hours'] = df['incident_timestamp'].dt.hour.between(9, 17)

        if 'login_time' in df.columns:
            df['login_hour'] = df['login_time'].dt.hour
            df['login_is_business_hours'] = df['login_time'].dt.hour.between(9, 17)

        return df

    def get_data_quality_report(self) -> Dict:
        """Generate data quality report."""
        report = {
            'incidents': {},
            'logins': {},
            'merged': {}
        }

        if self.incidents_df is not None:
            report['incidents'] = {
                'total_records': len(self.incidents_df),
                'date_range': f"{self.incidents_df['timestamp'].min()} to {self.incidents_df['timestamp'].max()}",
                'unique_ips': self.incidents_df['source_ip'].nunique(),
                'missing_values': self.incidents_df.isnull().sum().to_dict(),
                'severity_distribution': self.incidents_df['severity'].value_counts().to_dict()
            }

        if self.logins_df is not None:
            report['logins'] = {
                'total_records': len(self.logins_df),
                'date_range': f"{self.logins_df['login_time'].min()} to {self.logins_df['login_time'].max()}",
                'unique_ips': self.logins_df['ip_address'].nunique(),
                'missing_values': self.logins_df.isnull().sum().to_dict(),
                'success_rate': self.logins_df['success'].mean()
            }

        if self.merged_df is not None:
            report['merged'] = {
                'total_records': len(self.merged_df),
                'correlated_events': len(self.merged_df.dropna(subset=['login_id']))
            }

        return report

    def export_for_powerbi(self, output_dir: str = "dashboard/data"):
        """Export cleaned data for Power BI consumption."""
        import os
        os.makedirs(output_dir, exist_ok=True)

        if self.incidents_df is not None:
            self.incidents_df.to_csv(f"{output_dir}/incidents_cleaned.csv", index=False)
            logger.info(f"Exported incidents data to {output_dir}/incidents_cleaned.csv")

        if self.logins_df is not None:
            self.logins_df.to_csv(f"{output_dir}/logins_cleaned.csv", index=False)
            logger.info(f"Exported logins data to {output_dir}/logins_cleaned.csv")

        if self.merged_df is not None:
            self.merged_df.to_csv(f"{output_dir}/security_events_merged.csv", index=False)
            logger.info(f"Exported merged data to {output_dir}/security_events_merged.csv")


def main():
    """Main ETL pipeline execution."""
    preprocessor = DataPreprocessor()

    # Load data
    incidents_df = preprocessor.load_incidents_data("data/incidents.csv")
    logins_df = preprocessor.load_logins_data("data/logins.csv")

    # Merge datasets
    merged_df = preprocessor.merge_datasets()

    # Generate quality report
    quality_report = preprocessor.get_data_quality_report()
    logger.info("Data Quality Report:")
    for dataset, metrics in quality_report.items():
        logger.info(f"{dataset.upper()}: {metrics}")

    # Export for Power BI
    preprocessor.export_for_powerbi()

    logger.info("ETL pipeline completed successfully")


if __name__ == "__main__":
    main()
