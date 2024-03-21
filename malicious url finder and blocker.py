#!/usr/bin/env python
# coding: utf-8

# In[4]:


# get_ipython().system('pip install lightgbm')
# get_ipython().system('pip install wordcloud')


# In[5]:


import pandas as pd
import itertools
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import xgboost as xgb
from lightgbm import LGBMClassifier
import os
import seaborn as sns
from wordcloud import WordCloud


# In[6]:


df = pd.read_csv("malicious_phish.csv")

print(df.shape)
df.head()


# In[7]:


df.type.value_counts()


# In[8]:


df_phish = df[df.type == "phishing"]
df_malware = df[df.type == "malware"]
df_deface = df[df.type == "defacement"]
df_benign = df[df.type == "benign"]


# In[9]:

phish_url = " ".join(i for i in df_phish.url)


# In[10]:


malware_url = " ".join(i for i in df_malware.url)

# In[11]:


deface_url = " ".join(i for i in df_deface.url)


# In[12]:


benign_url = " ".join(i for i in df_benign.url)


# In[63]:


import re


# Use of IP or not in domain
def having_ip_address(url):
    match = re.search(
        "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|"  # IPv4
        "((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)"  # IPv4 in hexadecimal
        "(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}",
        url,
    )  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0


df["use_of_ip"] = df["url"].apply(lambda i: having_ip_address(i))


# In[14]:


from urllib.parse import urlparse


def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0


df["abnormal_url"] = df["url"].apply(lambda i: abnormal_url(i))


# In[15]:


# get_ipython().system("pip install googlesearch-python")


# In[16]:


from googlesearch import search


# In[17]:


def google_index(url):
    site = search(url, 5)
    return 1 if site else 0


df["google_index"] = df["url"].apply(lambda i: google_index(i))


# In[18]:


def count_dot(url):
    count_dot = url.count(".")
    return count_dot


df["count."] = df["url"].apply(lambda i: count_dot(i))
df.head()


# In[19]:


def count_www(url):
    url.count("www")
    return url.count("www")


df["count-www"] = df["url"].apply(lambda i: count_www(i))


def count_atrate(url):

    return url.count("@")


df["count@"] = df["url"].apply(lambda i: count_atrate(i))


def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count("/")


df["count_dir"] = df["url"].apply(lambda i: no_of_dir(i))


def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count("//")


df["count_embed_domian"] = df["url"].apply(lambda i: no_of_embed(i))


def shortening_service(url):
    match = re.search(
        "bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
        "yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
        "short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
        "doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"
        "db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|"
        "q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
        "x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
        "tr\.im|link\.zip\.net",
        url,
    )
    if match:
        return 1
    else:
        return 0


df["short_url"] = df["url"].apply(lambda i: shortening_service(i))


# In[20]:


def count_https(url):
    return url.count("https")


df["count-https"] = df["url"].apply(lambda i: count_https(i))


def count_http(url):
    return url.count("http")


df["count-http"] = df["url"].apply(lambda i: count_http(i))


# In[21]:


def count_per(url):
    return url.count("%")


df["count%"] = df["url"].apply(lambda i: count_per(i))


def count_ques(url):
    return url.count("?")


df["count?"] = df["url"].apply(lambda i: count_ques(i))


def count_hyphen(url):
    return url.count("-")


df["count-"] = df["url"].apply(lambda i: count_hyphen(i))


def count_equal(url):
    return url.count("=")


df["count="] = df["url"].apply(lambda i: count_equal(i))


def url_length(url):
    return len(str(url))


# Length of URL
df["url_length"] = df["url"].apply(lambda i: url_length(i))
# Hostname Length


def hostname_length(url):
    return len(urlparse(url).netloc)


df["hostname_length"] = df["url"].apply(lambda i: hostname_length(i))

df.head()


def suspicious_words(url):
    match = re.search(
        "PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr",
        url,
    )
    if match:
        return 1
    else:
        return 0


df["sus_url"] = df["url"].apply(lambda i: suspicious_words(i))


def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits


df["count-digits"] = df["url"].apply(lambda i: digit_count(i))


def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters


df["count-letters"] = df["url"].apply(lambda i: letter_count(i))

df.head()


# In[22]:


# get_ipython().system("pip install tld")


# In[23]:


# Importing dependencies
from urllib.parse import urlparse
from tld import get_tld
import os.path


# First Directory Length
def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split("/")[1])
    except:
        return 0


df["fd_length"] = df["url"].apply(lambda i: fd_length(i))

# Length of Top Level Domain
df["tld"] = df["url"].apply(lambda i: get_tld(i, fail_silently=True))


def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1


df["tld_length"] = df["tld"].apply(lambda i: tld_length(i))


# In[24]:


# df = df.drop("tld",1)
df = df.drop("tld", axis=1)


# In[25]:


df.columns


# In[26]:


df["type"].value_counts()


# In[27]:


import seaborn as sns


# In[39]:


from sklearn.preprocessing import LabelEncoder

lb_make = LabelEncoder()
df["type_code"] = lb_make.fit_transform(df["type"])
df["type_code"].value_counts()


# In[40]:


# Predictor Variables
# filtering out google_index as it has only 1 value
X = df[
    [
        "use_of_ip",
        "abnormal_url",
        "count.",
        "count-www",
        "count@",
        "count_dir",
        "count_embed_domian",
        "short_url",
        "count-https",
        "count-http",
        "count%",
        "count?",
        "count-",
        "count=",
        "url_length",
        "hostname_length",
        "sus_url",
        "fd_length",
        "tld_length",
        "count-digits",
        "count-letters",
    ]
]

# Target Variable
y = df["type_code"]


# In[41]:


X.head()


# In[42]:


X.columns


# In[43]:


X_train, X_test, y_train, y_test = train_test_split(
    X, y, stratify=y, test_size=0.2, shuffle=True, random_state=5
)


# In[44]:


from sklearn.ensemble import RandomForestClassifier
from sklearn import metrics

rf = RandomForestClassifier(n_estimators=100, max_features="sqrt")
rf.fit(X_train, y_train)
y_pred_rf = rf.predict(X_test)
print(
    classification_report(
        y_test, y_pred_rf, target_names=["benign", "defacement", "phishing", "malware"]
    )
)

score = metrics.accuracy_score(y_test, y_pred_rf)
print("accuracy:   %0.3f" % score)


# In[47]:


lgb = LGBMClassifier(
    objective="multiclass", boosting_type="gbdt", n_jobs=5, silent=True, random_state=5
)
LGB_C = lgb.fit(X_train, y_train)


y_pred_lgb = LGB_C.predict(X_test)
print(
    classification_report(
        y_test, y_pred_lgb, target_names=["benign", "defacement", "phishing", "malware"]
    )
)

score = metrics.accuracy_score(y_test, y_pred_lgb)
print("accuracy:   %0.3f" % score)


# In[50]:


xgb_c = xgb.XGBClassifier(n_estimators=100)
xgb_c.fit(X_train, y_train)
y_pred_x = xgb_c.predict(X_test)
print(
    classification_report(
        y_test, y_pred_x, target_names=["benign", "defacement", "phishing", "malware"]
    )
)


score = metrics.accuracy_score(y_test, y_pred_x)
print("accuracy:   %0.3f" % score)


# In[53]:


def main(url):

    status = []

    status.append(having_ip_address(url))
    status.append(abnormal_url(url))
    status.append(count_dot(url))
    status.append(count_www(url))
    status.append(count_atrate(url))
    status.append(no_of_dir(url))
    status.append(no_of_embed(url))

    status.append(shortening_service(url))
    status.append(count_https(url))
    status.append(count_http(url))

    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))

    status.append(url_length(url))
    status.append(hostname_length(url))
    status.append(suspicious_words(url))
    status.append(digit_count(url))
    status.append(letter_count(url))
    status.append(fd_length(url))
    tld = get_tld(url, fail_silently=True)

    status.append(tld_length(tld))

    return status


# In[54]:


def get_prediction_from_url(test_url):
    features_test = main(test_url)
    # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
    features_test = np.array(features_test).reshape((1, -1))

    pred = lgb.predict(features_test)
    if int(pred[0]) == 0:

        res = "SAFE"
        return res
    elif int(pred[0]) == 1.0:

        res = "DEFACEMENT"
        return res
    elif int(pred[0]) == 2.0:
        res = "PHISHING"
        return res

    elif int(pred[0]) == 3.0:

        res = "MALWARE"
        return res


# In[62]:

# Test model
# urls = ["titaniumcorporate.co.za", "en.wikipedia.org/wiki/North_Dakota"]
# for url in urls:
#     print(get_prediction_from_url(url))


import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import platform
import os


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
        root.geometry("450x250")
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
            if not (
                ("https://" in UrlStr) or ("http://" in UrlStr) or ("www." in UrlStr)
            ):
                messagebox.showerror(
                    "Erorr !!", "Please Tybe Full Url [ Ex: https://www.instagram.com ]"
                )
                return
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
