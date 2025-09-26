import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor

# Custom scanner modules
from scanner.iam_scanner import (
    get_overly_permissive_policies,
    get_users_without_mfa,
    get_inactive_users,
    get_unused_access_keys,
)
from scanner.s3_scanner import get_public_buckets

# ----------------------
# Streamlit Page Setup
# ----------------------
st.set_page_config(page_title="AWS IAM & S3 Scanner", layout="wide")
st.title("AWS IAM & S3 Misconfiguration Detector")
st.markdown(
    "Scan your AWS account for misconfigurations in **IAM policies, users, keys, and S3 buckets**."
)

# ----------------------
# Function to Run All Scans Concurrently
# ----------------------
@st.cache_data(ttl=300)
def scan_aws_environment():
    """Run all IAM and S3 scans concurrently and return results."""
    with ThreadPoolExecutor() as executor:
        tasks = {
            "permissive_policies": executor.submit(get_overly_permissive_policies),
            "no_mfa_users": executor.submit(get_users_without_mfa),
            "inactive_users": executor.submit(get_inactive_users),
            "unused_keys": executor.submit(get_unused_access_keys),
            "public_buckets": executor.submit(get_public_buckets),
        }
        # Collect results from all futures
        return {key: future.result() for key, future in tasks.items()}


# ----------------------
# Run Scan and Show Spinner
# ----------------------
with st.spinner("Scanning AWS for IAM & S3 misconfigurations..."):
    results = scan_aws_environment()

# Extract results
permissive_policies = results["permissive_policies"]
no_mfa_users = results["no_mfa_users"]
inactive_users = results["inactive_users"]
unused_keys = results["unused_keys"]
public_buckets = results["public_buckets"]

# ----------------------
# Display Quick Metrics
# ----------------------
st.subheader("Quick Overview")
col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Overly Permissive Policies", len(permissive_policies))
col2.metric("Users Without MFA", len(no_mfa_users))
col3.metric("Inactive Users", len(inactive_users))
col4.metric("Unused Access Keys", len(unused_keys))
col5.metric("Public S3 Buckets", len(public_buckets))

# ----------------------
# Pie Chart of Issues
# ----------------------
issue_counts = {
    "Permissive Policies": len(permissive_policies),
    "No MFA Users": len(no_mfa_users),
    "Inactive Users": len(inactive_users),
    "Unused Keys": len(unused_keys),
    "Public Buckets": len(public_buckets),
}

# Filter out zero-value categories
issue_counts = {k: v for k, v in issue_counts.items() if v > 0}

if issue_counts:
    fig, ax = plt.subplots(figsize=(2.5, 2.5))
    wedges, texts, autotexts = ax.pie(
        issue_counts.values(),
        labels=None,
        autopct="%1.1f%%",
        startangle=90,
        pctdistance=0.8,
        textprops={"fontsize": 6},
    )
    ax.axis("equal")
    ax.legend(
        wedges,
        issue_counts.keys(),
        title="Issue Type",
        loc="center left",
        bbox_to_anchor=(1, 0, 0.5, 1),
        fontsize=6,
    )
    st.pyplot(fig, clear_figure=True)
else:
    st.success("No issues detected! 🎉")

# ----------------------
# Helper: Display and Download DataFrames
# ----------------------
def display_and_download(df, heading, filename):
    st.subheader(heading)
    if df.empty:
        st.success("No issues found.")
    else:
        st.dataframe(df, use_container_width=True)
        csv_data = df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label=f"Download {heading} as CSV",
            data=csv_data,
            file_name=filename,
            mime="text/csv",
        )

# ----------------------
# Tabs for Detailed View
# ----------------------
tabs = st.tabs([
    "Permissive Policies",
    "Users Without MFA",
    "Inactive Users",
    "Unused Keys",
    "Public S3 Buckets",
])

with tabs[0]:
    display_and_download(pd.DataFrame(permissive_policies), "Overly Permissive IAM Policies", "permissive_policies.csv")
with tabs[1]:
    display_and_download(pd.DataFrame(no_mfa_users), "Users Without MFA", "users_without_mfa.csv")
with tabs[2]:
    display_and_download(pd.DataFrame(inactive_users), "Inactive IAM Users", "inactive_users.csv")
with tabs[3]:
    display_and_download(pd.DataFrame(unused_keys), "Unused Access Keys", "unused_keys.csv")
with tabs[4]:
    display_and_download(pd.DataFrame(public_buckets), "Public S3 Buckets", "public_buckets.csv")

# ----------------------
# Alerts for Critical Findings
# ----------------------
if public_buckets:
    st.error(" Critical: Public S3 Buckets detected!")
if no_mfa_users:
    st.warning(" High Risk: Some users do not have MFA enabled.")
