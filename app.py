import joblib
import urllib.parse 
import pandas as pd
import re
import requests
from bs4 import BeautifulSoup

# Read before running the script!

# Step 1: Install Required Libraries
# If you haven't installed the required libraries yet, please follow these instructions:
# Open your terminal or command prompt and run the following commands:

# For joblib (run the command below in the terminal)
# pip install joblib

# For pandas (run the command below in the terminal)
# pip install pandas

# For numpy (run the command below in the terminal)
# pip install numpy

# For scikit-learn (run the command below in the terminal)
# pip install scikit-learn

# For beautifulsoup4 (run the command below in the terminal)
# pip install beautifulsoup4

# For Flask (run the command below in the terminal)
# pip install Flask

# Step 2: Run the Flask Application
# In the terminal, navigate to the directory containing the 'app.py' file.
# Then run the following command to start the Flask application:

# python3 app.py run

# Step 3: Access the Web Application
# Open a web browser and go to http://localhost:5000/ or http://127.0.0.1:5000/
# You should see a form where you can enter the URL.
# Enter the URL you want to check for phishing and click the "Submit" button.

# Step 4: View the Prediction
# After submitting the URL, the application will process it and display the prediction.
# You will see a message indicating the likelihood of the URL being a phishing link.

# Defining Features

selected_features = [
    'ip',
    'https_token',
    'domain_with_copyright',
    'google_index',
    'page_rank',
    'url_length',
    'total_of_www',
    'punycode',
    'phish_hints',
    'total_of.',
    'total_of?',
    'total_of=',
    'total_of/',
    'ratio_digits_url',
    'hostname_length',
    'total_of_com',
    'shortening_service'
]

# Load the model
model_path = "model_AI_detector-I2.pkl"
model = joblib.load(open(model_path, 'rb'))
print("Model loaded successfully", model)
# Functions for extracting features from URL
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '[0-9a-fA-F]{7}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0

def https_token(scheme):
    if scheme == 'https':
        return 0
    return 1

def domain_with_copyright(domain, content):
    try:
        m = re.search(u'(\N{COPYRIGHT SIGN}|\N{TRADE MARK SIGN}|\N{REGISTERED SIGN})', content)
        _copyright = content[m.span()[0]-50:m.span()[0]+50]
        if domain.lower() in _copyright.lower():
            return 0
        else:
            return 1 
    except:
        return 0

def google_index(url):
    user_agent =  'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
    headers = {'User-Agent' : user_agent}
    query = {'q': 'site:' + url}
    google = "https://www.google.com/search?" + urllib.parse.urlencode(query)
    data = requests.get(google, headers=headers)
    data.encoding = 'ISO-8859-1'
    soup = BeautifulSoup(str(data.content), "html.parser")
    try:
        if 'Our systems have detected unusual traffic from your computer network.' in str(soup):
            return -1
        check = soup.find(id="rso").find("div").find("div").find("a")
        if check and check['href']:
            return 0
        else:
            return 1
    except AttributeError:
        return 1

def page_rank(domain):
    url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    try:
        request = requests.get(url, headers={'API-OPR': "sksss4cw4soc8o00cg4ggsgcc88cccsk80oscs00"})
        result = request.json()
        result = result['response'][0]['page_rank_integer']
        if result:
            return result
        else:
            return 0
    except:
        return -1

def url_length(url):
    return len(url) 

def total_of_www(words_raw):
    count = 0
    for word in words_raw:
        if not word.find('www') == -1:
            count += 1
    return count

def punycode(full_url):
    if full_url.startswith("http://xn--") or full_url.startswith("http://xn--"):
        return 1
    else:
        return 0
    
def phish_hints(url_path):
    HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view']
    count = 0
    for hint in HINTS:
        count += url_path.lower().count(hint)
    return count

def total_of_dot(full_url):
    return full_url.count('.')

def total_of_question_mark(full_url):
    return full_url.count('?')

def total_of_equal(full_url):
    return full_url.count('=')

def total_of_slash(full_url):
    return full_url.count('/')

def ratio_digits(hostname):
    return len(re.sub("[^0-9]", "", hostname))/len(hostname)

def total_and(full_url):
    return full_url.count('&')

def shortening_service(full_url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      full_url)
    if match:
        return 1
    else:
        return 0


# Preprocess URL and extract features
def process_url(full_url):
    features = {}

    # Extract the domain, subdomain, and path
    parsed_url = urllib.parse.urlparse(full_url)
    hostname = parsed_url.hostname
    path = parsed_url.path
    scheme = parsed_url.scheme
    
    # Check if the domain, subdomain, and path is null
    if hostname:
        features['ip'] = having_ip_address(hostname)
        features['https_token'] = https_token(scheme)
        features['domain_with_copyright'] = domain_with_copyright(hostname, "")
        features['google_index'] = google_index(hostname)
        features['page_rank'] = page_rank(hostname)
        features['url_length'] = url_length(full_url)
        features['total_of_www'] = total_of_www(path)
        features['punycode'] = punycode(hostname)
        features['phish_hints'] = phish_hints(path)
        features['total_of.'] = total_of_dot(full_url)
        features['total_of?'] = total_of_question_mark(full_url)
        features['total_of='] = total_of_equal(full_url)
        features['total_of/'] = total_of_slash(full_url)
        features['ratio_digits_url'] = ratio_digits(hostname)
        features['hostname_length'] = len(hostname)
        features['total_of_com'] = total_and(full_url)
        features['shortening_service'] = shortening_service(full_url)

    df_inputs = pd.DataFrame([features], columns=selected_features)
    return df_inputs

# Define Flask routes
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    features = process_url(url)
    prediction = model.predict(features)
    return render_template('index.html', prediction="The link has {:.2f}% chance of being a phishing link".format(prediction[0] * 100))

if __name__ == '__main__':
    app.run(debug=True)
