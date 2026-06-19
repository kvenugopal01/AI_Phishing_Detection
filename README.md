# AI Phishing Detection

## Overview

AI Phishing Detection is a machine learning-based web application that detects whether a URL is legitimate or potentially phishing. The project uses feature extraction techniques and a trained machine learning model to analyze URLs and provide real-time predictions.

## Features

* Detects phishing websites using Machine Learning
* Extracts multiple URL-based security features
* User-friendly web interface built with Flask
* Real-time URL analysis and prediction
* Fast and lightweight deployment

## Tech Stack

* Python
* Flask
* Scikit-learn
* Pandas
* NumPy
* HTML
* CSS

## Project Structure

```
AI_Phishing_Detection/
│
├── app.py
├── train_model.py
├── feature_extraction.py
├── phishing_model.pkl
├── dataset/
│   └── dataset.csv
├── templates/
│   └── index.html
├── static/
│   └── style.css
├── README.md
└── .gitignore
```

## Installation

### Clone Repository

```bash
git clone https://github.com/kvenugopal01/AI_Phishing_Detection.git
cd AI_Phishing_Detection
```

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Virtual Environment

**Windows**

```bash
venv\Scripts\activate
```

**Mac/Linux**

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

## Run Application

```bash
python app.py
```

Open your browser and visit:

```
http://127.0.0.1:5000
```

## How It Works

1. User enters a URL.
2. The system extracts security-related URL features.
3. The trained machine learning model analyzes the features.
4. The application predicts whether the URL is:

   * Legitimate Website
   * Phishing Website

## Machine Learning Workflow

* Data Collection
* Data Preprocessing
* Feature Extraction
* Model Training
* Model Evaluation
* Deployment with Flask

## Future Enhancements

* Deep Learning-based Detection
* Real-time Threat Intelligence Integration
* Browser Extension Support
* API Integration
* Enhanced Visualization Dashboard

## Author

**K. Venu Gopal**

* GitHub: https://github.com/kvenugopal01
* LinkedIn: https://www.linkedin.com/in/kommanaboyina-venu-gopal-520a95339/

## License

This project is developed for educational and research purposes.
