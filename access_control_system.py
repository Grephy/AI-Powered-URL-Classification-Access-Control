import joblib
import numpy as np
import re
from urllib.parse import urlparse
from tld import get_tld
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
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


# Function to predict if a URL is malicious
def get_prediction_from_url(test_url):
    features_test = main(test_url)
    features_test = np.array(features_test).reshape((1, -1))

    pred = LGB_C.predict(features_test)
    if int(pred[0]) == 0:
        return "SAFE"
    elif int(pred[0]) == 1:
        return "DEFACEMENT"
    elif int(pred[0]) == 2:
        return "PHISHING"
    elif int(pred[0]) == 3:
        return "MALWARE"


# Function to check if URL is malicious using the ML model
def check_url_malicious(url):
    # Implement your ML model prediction code here
    # For demonstration, let's assume get_prediction_from_url is your function for model prediction
    result = get_prediction_from_url(url)
    return result


# Get the path to the hosts file based on the operating system
if platform.system() == "Windows":
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
else:
    hosts_path = "/etc/hosts"

# save the original permission mode
original_mode = os.stat(hosts_path).st_mode


class API:

    def ReadHosts(LISTBOX):
        for i in (
            open(r"C:\Windows\System32\drivers\etc\hosts", "r").read().splitlines()
        ):
            if (i.startswith("#")) or (i.strip() == ""):
                continue
            Cmnd = i.split(" ")
            LISTBOX.insert(0, " " + Cmnd[len(Cmnd) - 1])


class GuiApp:
    def __init__(self, root):
        root.geometry("550x300")
        root.title("Web Guard")

        # Variables
        URL = tk.StringVar()
        prediction_result = tk.StringVar()

        # Text Bar
        def placeholder(varr):
            if str(URL.get()) == "< URL Here >":
                URLBar.delete(0, tk.END)
            else:
                print()

        URLBar = ttk.Entry(width=71, textvariable=URL)
        URLBar.place(x=7, y=20)
        URLBar.bind("<Button>", placeholder)
        URLBar.insert(0, "< URL Here >")

        # Buttons
        def AllowAccess():
            # Get the path to the hosts file based on the operating system
            if platform.system() == "Windows":
                hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            else:
                hosts_path = "/etc/hosts"

            # # save the original permission mode
            # original_mode = os.stat(hosts_path).st_mode
            os.chmod(hosts_path, 0o200)

        def DenyAccess():
            # Get the path to the hosts file based on the operating system
            if platform.system() == "Windows":
                hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            else:
                hosts_path = "/etc/hosts"

            # Change the permissions of the hosts file to read and write
            os.chmod(hosts_path, original_mode)

        def Quit():
            # Get the path to the hosts file based on the operating system
            if platform.system() == "Windows":
                hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            else:
                hosts_path = "/etc/hosts"

            # restore the original permission mode
            os.chmod(hosts_path, original_mode)
            exit()

        def Add():
            UrlStr = str(URL.get()).strip()
            # if not (
            #     ("https://" in UrlStr) or ("http://" in UrlStr) or ("www." in UrlStr)
            # ):
            #     messagebox.showerror(
            #         "Erorr !!", "Please Tybe Full Url [ Ex: https://www.instagram.com ]"
            #     )
            #     return
            if UrlStr in list(listbox.get(0, last=10000)):
                messagebox.showerror("Error !!", "This URL is Already Added ..")
                return
            listbox.insert(0, UrlStr)

        def Remove():
            listbox.delete(tk.ANCHOR)

        def Update():
            AllWebsites = list(listbox.get(0, last=10000))
            FinalWebsites = []
            # Translate URL Syntax
            for data in AllWebsites:
                if data.startswith(" "):
                    FinalWebsites.append("127.0.0.1 " + data.strip())
                    continue
                S = data.replace("https://", "").replace("http://", "")
                if "www." in S:
                    with_www = str(S)
                    without_www = S.replace("www.", "")
                    FinalWebsites.append("127.0.0.1 " + with_www)
                    FinalWebsites.append("127.0.0.1 " + without_www)
                else:
                    FinalWebsites.append("127.0.0.1 " + S)

            # C:\Windows\System32\drivers\etc\hosts
            README = []
            for data in (
                open(r"C:\Windows\System32\drivers\etc\hosts", "r").read().splitlines()
            ):
                if (data.startswith("#")) or (data.strip() == ""):
                    README.append(data)

            try:
                Hosts = open(r"C:\Windows\System32\drivers\etc\hosts", "w")
                Hosts.write("\n".join(README) + "\n")
                Hosts.write("\n".join(FinalWebsites))
                Hosts.close()
                messagebox.showinfo("Done !!", "Blocked List Has Updated ..")
            except Exception as AdminErr:
                ERROR = str(AdminErr)[: str(AdminErr).find(":") + 1] + " 'HOSTS_FILE'"
                messagebox.showerror(
                    "Admin Error !!", f"Please Run Program as Admin :\n{ERROR}"
                )

        addBtn = ttk.Button(root, text="Add", command=Add)
        addBtn.place(x=7, y=50)

        removeBtn = ttk.Button(root, text="Remove", command=Remove)
        removeBtn.place(x=132, y=50)

        updateBtn = ttk.Button(root, text="Update", command=Update)
        updateBtn.place(x=257, y=50)

        allowaccessBtn = ttk.Button(root, text="Allow Access", command=AllowAccess)
        allowaccessBtn.place(x=7, y=85)

        denyaccessBtn = ttk.Button(root, text="Deny Access", command=DenyAccess)
        denyaccessBtn.place(x=132, y=85)

        quitBtn = ttk.Button(root, text="Exit", command=Quit)
        quitBtn.place(x=257, y=85)

        # Check Malicious Button
        def check_malicious():
            url = URL.get().strip()
            if url:
                result = check_url_malicious(url)
                messagebox.showinfo("Malicious Check Result", f"The URL is {result}")
            else:
                messagebox.showerror("Error", "Please enter a URL.")

        checkBtn = ttk.Button(root, text="Check Malicious", command=check_malicious)
        checkBtn.place(x=7, y=120)

        # Result Label - Not used in this version

        # Sites List
        listbox = tk.Listbox(root, width=71, height=5)
        listbox.place(x=7, y=150)
        # API.ReadHosts(listbox) - You might need to call this function to populate the list initially


if __name__ == "__main__":
    TKGui = tk.Tk()
    TKGui.resizable(0, 0)
    GuiApp(TKGui)
    TKGui.mainloop()
