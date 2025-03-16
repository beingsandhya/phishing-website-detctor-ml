import streamlit as st
import pandas as pd
import pickle
import re
from urllib.parse import urlparse
import tldextract
import whois
import datetime
import requests


with open("XGBoostClassifier.pickle.dat", "rb") as file:
    model = pickle.load(file)




def extract_features(url):
    parsed_url = urlparse(url)
    domain_info = tldextract.extract(url)
    
    features = {
        "Have_IP": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed_url.netloc) else 0,
        "Have_At": 1 if "@" in url else 0,
        "URL_Length": len(url),
        "URL_Depth": url.count("/"),
        "Redirection": 1 if "//" in url[7:] else 0,
        "https_Domain": 1 if "https" in parsed_url.scheme else 0,
        "TinyURL": 1 if len(url) < 20 else 0,
        "Prefix/Suffix": 1 if "-" in parsed_url.netloc else 0,
        "DNS_Record": 1,
        "Web_Traffic": 0,
        "Domain_Age": 0,
        "Domain_End": 0,
        "iFrame": 0,
        "Mouse_Over": 0,
        "Right_Click": 0,
        "Web_Forwards": 0,
    }

  
    try:
        domain_info = whois.whois(domain_info.registered_domain)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        if creation_date and expiration_date:
            features["Domain_Age"] = (datetime.datetime.now() - creation_date).days
            features["Domain_End"] = (expiration_date - datetime.datetime.now()).days
    except:
        features["DNS_Record"] = 0

  
    try:
        alexa_rank = requests.get(f"https://www.alexa.com/siteinfo/{parsed_url.netloc}")
        features["Web_Traffic"] = int(re.search(r"Global Rank: ([\d,]+)", alexa_rank.text).group(1).replace(",", ""))
    except:
        features["Web_Traffic"] = 0

    return pd.DataFrame([features])


st.sidebar.image("logo.jpeg", width=250)  

st.title(" Phishing Website Detector ")
st.markdown("Enter a URL to check if it is phishing or safe.")




url = st.text_input("🔗 Enter the URL", "https://example.com")

if st.button("Detect"):
    if url:
        features_df = extract_features(url)
        prediction = model.predict(features_df)[0]
        
        if prediction == 1:
            st.error("⚠️ This URL is **Phishing**! Do not visit.")
        else:
            st.success(" This URL is **Safe**!")
    else:
        st.warning("Please enter a valid URL.")



















      




































































































































































