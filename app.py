import streamlit as st
import pandas as pd
import pickle
import re
from urllib.parse import urlparse
import tldextract
import whois
import datetime


with open("XGBoostClassifier.pickle.dat", "rb") as file:
    model = pickle.load(file)


def extract_features(url):
    parsed_url = urlparse(url)
    domain_info = tldextract.extract(url)

    features = {
        "Have_At": 1 if "@" in url else 0,
        "URL_Length": len(url),
        "URL_Depth": url.count("/"),
        "Prefix_Suffix": 1 if "-" in parsed_url.netloc else 0,
        "Domain_Age": 0,  
    }

    
    try:
        domain_details = whois.whois(domain_info.registered_domain)
        if isinstance(domain_details.creation_date, list):
            creation_date = domain_details.creation_date[0]
        else:
            creation_date = domain_details.creation_date
        
        if creation_date:
            features["Domain_Age"] = (datetime.datetime.now() - creation_date).days
    except:
        pass  

    return pd.DataFrame([features])


st.title(" Phishing Website Detector")
st.markdown("Enter a URL to detect .")


url = st.text_input("🔗 Enter the URL", "https://example.com")

if st.button("DETECT"):
    if url:
        features_df = extract_features(url)
        prediction = model.predict(features_df)[0]

        if prediction == 1:
            st.error("This URL is **Phishing**! Do not visit.")
        else:
            st.success("✅ This URL is **Safe**!")
    else:
        st.warning("Please enter a valid URL.")







































































































































































