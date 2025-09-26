import streamlit as st
import pandas as pd
from scanner.iam_scanner import (
    get_overly_permissive_policies,
    get_users_without_mfa,
    get_inactive_users,
    get_unused_access_keys,
)
from scanner.s3_scanner import get_public_buckets

st.set_page_config(page_title="IAM Misconfiguration Detection Tool", layout="wide")
st.title("IAM Misconfiguration Detection Tool (AWS-IMDT+)")
st.markdown("Advanced IAM & S3 misconfiguration scanner using Boto3 + Streamlit")

with st.spinner("Scanning IAM Policies..."):
    perms = get_overly_permissive_policies()
with st.spinner("Scanning MFA..."):
    no_mfa = get_users_without_mfa()
with st.spinner("Scanning Inactive Users..."):
    inactive = get_inactive_users()
with st.spinner("Scanning Unused Access Keys..."):
    unused = get_unused_access_keys()
with st.spinner("Checking Public S3 Buckets..."):
    public_buckets = get_public_buckets()

st.subheader("Overly Permissive IAM Policies")
st.dataframe(pd.DataFrame(perms))

st.subheader("Users Without MFA")
st.dataframe(pd.DataFrame(no_mfa))

st.subheader("Inactive IAM Users")
st.dataframe(pd.DataFrame(inactive))

st.subheader("Unused Access Keys")
st.dataframe(pd.DataFrame(unused))

st.subheader("Public S3 Buckets")
st.dataframe(pd.DataFrame(public_buckets))
