🔐 Mitigating DDoS Attacks in IoT Network Environment

📖 About the Project

With the rise of IoT devices, security has become a serious challenge. One of the biggest threats is Distributed Denial of Service (DDoS) attacks, where huge amounts of fake traffic can shut down real systems.

In this project, I built a Machine Learning based system that can detect and classify DDoS attacks in IoT network traffic.
I designed a Python Tkinter GUI where you can:

Upload network traffic datasets

Preprocess and clean the data

Train multiple ML models

Compare their performance

Predict attacks on new test data

This project is my hands-on attempt to combine machine learning + network security with an easy-to-use interface.

✨ Key Features

Upload and preprocess IoT attack datasets

Feature encoding, normalization, and dimensionality reduction (PCA)

Train and test 6 different ML algorithms

Get Accuracy, Precision, Recall, and F1 Score for each model

Visualize results with confusion matrix heatmaps and bar graphs

Predict unseen test data through the GUI

🧠 Algorithms I Used

Naive Bayes

Random Forest

Support Vector Machine (SVM)

K-Nearest Neighbors (KNN)

XGBoost

AdaBoost

I trained all these models and compared which one works best for detecting DDoS in IoT networks.

⚙️ How to Run

Clone the repo:

git clone https://github.com/your-username/ddos-iot-detection.git
cd ddos-iot-detection


Install required libraries:

pip install -r requirements.txt


Run the app:

python Main.py

📂 Dataset Info

The project uses IoT attack datasets such as:

DrDOS_DNS.csv

Syn.csv

UDP_LAG.csv
(and more…)

📌 If you want to test with your own dataset, just make sure the columns match the training dataset format.

📊 Results

Random Forest and SVM gave the best performance in my tests

Each model’s performance is shown using metrics and graphs

Confusion matrices make it clear where misclassifications happen

📜 Abstract

The Internet of Things (IoT) is rapidly expanding, connecting devices across homes, industries, and cities. However, this growth has also made IoT systems vulnerable to cyber threats such as Distributed Denial of Service (DDoS) attacks.

In this project, I developed a Machine Learning–based system to detect DDoS attacks in IoT network traffic. The solution preprocesses raw data, applies dimensionality reduction, and evaluates multiple algorithms including Random Forest, SVM, Naive Bayes, KNN, AdaBoost, and XGBoost. A user-friendly GUI was also built using Python’s Tkinter, making it easy to upload datasets, visualize attack distributions, compare model performance, and predict attacks in real time.

This project highlights how Machine Learning can be effectively applied to improve IoT network security and demonstrates the strengths of different algorithms in handling DDoS detection.
