import joblib
import numpy as np
import re
from urllib.parse import urlparse
from tld import get_tld
import tkinter as tk
from tkinter import ttk, messagebox
import platform
import os

# Load the model
try:
    LGB_C = joblib.load("lgb_model.pkl")
except FileNotFoundError:
    print("Error: The model file 'lgb_model.pkl' was not found. Train the model first.")
    exit()


# Feature extraction functions
def having_ip_address(url):
    match = re.search(
        r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\."
        r"([01]?\d\d?|2[0-4]\d|25[0-5])\/)|"
        r"((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)|"
        r"(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}",
        url,
    )
    return 1 if match else 0


def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    return 1 if match else 0


def count_dot(url):
    return url.count(".")


def count_www(url):
    return url.count("www")


def count_atrate(url):
    return url.count("@")


def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count("/")


def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count("//")


def shortening_service(url):
    match = re.search(
        r"bit\.ly|goo\.gl|shorte\.st|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
        r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|snipurl\.com|url4\.eu|twit\.ac|su\.pr",
        url,
    )
    return 1 if match else 0


def url_length(url):
    return len(str(url))


def hostname_length(url):
    return len(urlparse(url).netloc)


def suspicious_words(url):
    match = re.search(
        r"PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr",
        url,
    )
    return 1 if match else 0


def digit_count(url):
    return sum(char.isdigit() for char in url)


def letter_count(url):
    return sum(char.isalpha() for char in url)


def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split("/")[1])
    except IndexError:
        return 0


def tld_length(url):
    tld = get_tld(url, fail_silently=True)
    return len(tld) if tld else 0


# Combine feature extraction
def main(url):
    return [
        having_ip_address(url),
        abnormal_url(url),
        count_dot(url),
        count_www(url),
        count_atrate(url),
        no_of_dir(url),
        no_of_embed(url),
        shortening_service(url),
        url.count("https"),  # count-https
        url.count("http"),  # count-http
        url.count("%"),  # count%
        url.count("?"),  # count?
        url.count("-"),  # count-
        url.count("="),  # count=
        url_length(url),
        hostname_length(url),
        suspicious_words(url),
        fd_length(url),
        tld_length(url),
        digit_count(url),
        letter_count(url),
    ]


# Predict if a URL is malicious
def get_prediction_from_url(test_url):
    features_test = main(test_url)
    features_test = np.array(features_test).reshape((1, -1))
    pred = LGB_C.predict(features_test)
    return ["SAFE", "DEFACEMENT", "PHISHING", "MALWARE"][int(pred[0])]


# GUI for Access Control
class AccessControlSystem:
    def __init__(self, root):
        root.geometry("550x300")
        root.title("Access Control System")

        URL = tk.StringVar()

        URLBar = ttk.Entry(root, width=71, textvariable=URL)
        URLBar.place(x=7, y=20)
        URLBar.insert(0, "< Enter URL Here >")

        def check_malicious():
            url = URL.get().strip()
            if url:
                result = get_prediction_from_url(url)
                messagebox.showinfo(
                    "Malicious Check Result", f"The URL is classified as: {result}"
                )
            else:
                messagebox.showerror("Error", "Please enter a URL.")

        checkBtn = ttk.Button(root, text="Check URL", command=check_malicious)
        checkBtn.place(x=7, y=50)


# Run the GUI
if __name__ == "__main__":
    TKGui = tk.Tk()
    TKGui.resizable(0, 0)
    AccessControlSystem(TKGui)
    TKGui.mainloop()
