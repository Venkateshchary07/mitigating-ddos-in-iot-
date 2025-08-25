
import os
import tkinter as tk
from tkinter import filedialog, messagebox, Scrollbar, Text, Label, Button
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import webbrowser
import pickle
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, normalize
from sklearn.decomposition import PCA
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn import svm
from sklearn.neighbors import KNeighborsClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import threading

# Global Variables
filename = None
dataset = None
X = Y = None
X_train = X_test = y_train = y_test = None
labels = []
label_encoder = []
columns = types = pca = classifier = None
accuracy = []
precision = []
recall = []
fscore = []
feature_columns = []

# GUI Setup
main = tk.Tk()
main.title("Mitigating DDOS Attack In IOT Network Environment")
main.geometry("1300x1200")

text = Text(main, height=20, width=150)
scroll = Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=50, y=120)
text.config(font=('times', 12, 'bold'))

# Utility Functions
def getLabel(name):
    if name in labels:
        return labels.index(name)
    return -1

def uploadDataset():
    global filename, dataset, labels
    text.delete('1.0', tk.END)
    filename = filedialog.askdirectory(initialdir=".")
    if not filename:
        messagebox.showerror("Error", "No folder selected")
        return

    files = ["DrDOS_DNS.csv", "DrDOS_LDAP.csv", "DrDOS_MSSQL.csv", "DrDOS_NTP.csv",
             "DrDOS_NetBIOS.csv", "DrDOS_SNMP.csv", "DrDOS_SSDP.csv", "DrDOS_UDP.csv",
             "Syn.csv", "UDP_LAG.csv"]
    dataframes = []
    try:
        for f in files:
            path = os.path.join(filename, f)
            if os.path.exists(path):
                df = pd.read_csv(path)
                dataframes.append(df)
            else:
                text.insert(tk.END, f"Missing: {f}\n")
        dataset_df = pd.concat(dataframes)
        labels.clear()
        labels.extend(np.unique(dataset_df['Label']).tolist())
        text.insert(tk.END, str(dataset_df.head()) + "\n")
        dataset_df['Label'].value_counts().plot(kind="bar")
        plt.xlabel('DDOS Attacks')
        plt.ylabel('Number of Records')
        plt.title('Different Attacks found in dataset')
        plt.show()
        dataset_df.fillna(0, inplace=True)
        dataset_df.reset_index(drop=True, inplace=True)
        globals()['dataset'] = dataset_df
    except Exception as e:
        messagebox.showerror("Error", str(e))

def preprocessDataset():
    global X, Y, X_train, X_test, y_train, y_test, label_encoder, columns, types, pca, dataset, feature_columns
    if dataset is None:
        messagebox.showerror("Error", "Dataset not uploaded")
        return

    text.delete('1.0', tk.END)
    label_encoder.clear()
    columns = dataset.columns.tolist()
    types = dataset.dtypes.tolist()

    for i, col_type in enumerate(types):
        if col_type == 'object' and columns[i] != 'Label':
            le = LabelEncoder()
            dataset[columns[i]] = le.fit_transform(dataset[columns[i]].astype(str))
            label_encoder.append(le)
        elif columns[i] != 'Label':
            label_encoder.append(None)

    dataset.replace([np.inf, -np.inf], np.nan, inplace=True)
    dataset.fillna(0, inplace=True)
    feature_columns = dataset.drop(columns=['Label']).columns.tolist()

    Y = dataset['Label'].apply(lambda v: getLabel(v)).values
    X = dataset.drop(columns=['Label']).values

    X = normalize(X)
    pca = PCA(n_components=min(50, X.shape[1]))
    X = pca.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2)

    text.insert(tk.END, "Dataset after feature processing & normalization\n\n")
    text.insert(tk.END, f"{X[:5]}\n\n")
    text.insert(tk.END, f"Total records found in dataset : {X.shape[0]}\n")
    text.insert(tk.END, f"Total features found in dataset: {X.shape[1]}\n\n")
    text.insert(tk.END, "Dataset Train and Test Split\n\n")
    text.insert(tk.END, f"80% dataset records used to train ML algorithms : {X_train.shape[0]}\n")
    text.insert(tk.END, f"20% dataset records used to test ML algorithms  : {X_test.shape[0]}\n")

def predict():
    global label_encoder, labels, columns, types, pca, classifier, X_train, feature_columns
    text.delete('1.0', tk.END)

    filename = filedialog.askopenfilename(initialdir="testData")
    if not filename:
        messagebox.showerror("Error", "Please select a test CSV file")
        return

    try:
        testData = pd.read_csv(filename)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read test file:\n{str(e)}")
        return

    if 'Label' in testData.columns:
        testData = testData.drop(columns=['Label'])

    try:
        testData = testData[feature_columns]
    except Exception as e:
        messagebox.showerror("Error", "Test file columns must match training columns.\n" + str(e))
        return

    count = 0
    for i in range(len(columns)):
        col = columns[i]
        if col == 'Label' or col not in testData.columns:
            continue

        if types[i] == 'object':
            le = label_encoder[count]
            if le is not None:
                try:
                    testData[col] = le.transform(testData[col].astype(str))
                except:
                    testData[col] = le.fit_transform(testData[col].astype(str))
            count += 1
        else:
            count += 1

    testData.replace([np.inf, -np.inf], np.nan, inplace=True)
    testData.fillna(0, inplace=True)

    try:
        testData = testData.values

        if testData.shape[1] != X_train.shape[1]:
            messagebox.showerror("Error", f"Test data has {testData.shape[1]} features, but expected {X_train.shape[1]}")
            return

        testData = normalize(testData)
        testData = pca.transform(testData)
    except Exception as e:
        messagebox.showerror("Error", f"Failed during normalization or PCA:\n{str(e)}")
        return

    try:
        predictions = classifier.predict(testData)
    except Exception as e:
        messagebox.showerror("Error", f"Prediction failed:\n{str(e)}")
        return

    for i in range(len(predictions)):
        result_label = labels[predictions[i]]
        text.insert(tk.END, f"Test DATA : {testData[i]} ===> PREDICTED AS {result_label}\n\n")


def show_plot_in_thread():
    plt.show()

def calculateMetrics(name, y_pred):
    acc = accuracy_score(y_test, y_pred) * 100
    pre = precision_score(y_test, y_pred, average='macro', zero_division=0) * 100
    rec = recall_score(y_test, y_pred, average='macro') * 100
    f1 = f1_score(y_test, y_pred, average='macro') * 100

    accuracy.append(acc)
    precision.append(pre)
    recall.append(rec)
    fscore.append(f1)

    text.insert(tk.END, f"{name} Accuracy: {acc:.2f}%\n")
    text.insert(tk.END, f"{name} Precision: {pre:.2f}%\n")
    text.insert(tk.END, f"{name} Recall: {rec:.2f}%\n")
    text.insert(tk.END, f"{name} F1 Score: {f1:.2f}%\n\n")

    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='g', xticklabels=labels, yticklabels=labels, cmap='viridis')
    plt.title(f'{name} Confusion Matrix')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')

    plt.show(block=False)  # ✅ Non-blocking and safe

if not os.path.exists('model'):
    os.makedirs('model')

def trainModel(model, path):
    if os.path.exists(path):
        with open(path, 'rb') as f:
            return pickle.load(f)
    model.fit(X_train, y_train)
    with open(path, 'wb') as f:
        pickle.dump(model, f)
    return model

def runNaiveBayes():
    model = trainModel(GaussianNB(), 'model/nb.txt')
    calculateMetrics("Naive Bayes", model.predict(X_test))

def runRandomForest():
    global classifier
    model = trainModel(RandomForestClassifier(), 'model/rf.txt')
    classifier = model
    calculateMetrics("Random Forest", model.predict(X_test))

def runSVM():
    model = trainModel(svm.SVC(), 'model/svm.txt')
    calculateMetrics("SVM", model.predict(X_test))

def runXGBoost():
    model = trainModel(XGBClassifier(use_label_encoder=False, eval_metric='logloss'), 'model/xgb.txt')
    calculateMetrics("XGBoost", model.predict(X_test))

def runAdaBoost():
    model = trainModel(AdaBoostClassifier(), 'model/adb.txt')
    calculateMetrics("AdaBoost", model.predict(X_test))

def runKNN():
    model = trainModel(KNeighborsClassifier(n_neighbors=2), 'model/knn.txt')
    calculateMetrics("KNN", model.predict(X_test))

def predict():
    global label_encoder, labels, columns, types, pca, classifier, feature_columns
    text.delete('1.0', tk.END)

    filename = filedialog.askopenfilename(initialdir="testData")
    if not filename:
        messagebox.showerror("Error", "Please select a test CSV file")
        return

    try:
        testData = pd.read_csv(filename)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read test file:\n{str(e)}")
        return

    if 'Label' in testData.columns:
        testData = testData.drop(columns=['Label'])

    try:
        testData = testData[feature_columns]  # Match column structure
    except Exception as e:
        messagebox.showerror("Error", "Test file columns must match training columns.\n" + str(e))
        return

    count = 0
    for i in range(len(columns)):
        col = columns[i]
        if col == 'Label' or col not in testData.columns:
            continue

        if types[i] == 'object':
            le = label_encoder[count]
            if le is not None:
                try:
                    testData[col] = le.transform(testData[col].astype(str))
                except:
                    testData[col] = le.fit_transform(testData[col].astype(str))
            count += 1
        else:
            count += 1

    testData.replace([np.inf, -np.inf], np.nan, inplace=True)
    testData.fillna(0, inplace=True)

    try:
        testData = testData.values

        expected_features = len(feature_columns)
        if testData.shape[1] != expected_features:
            messagebox.showerror("Error", f"Test data has {testData.shape[1]} features, but expected {expected_features}")
            return

        testData = normalize(testData)
        testData = pca.transform(testData)
    except Exception as e:
        messagebox.showerror("Error", f"Failed during normalization or PCA:\n{str(e)}")
        return

    try:
        predictions = classifier.predict(testData)
    except Exception as e:
        messagebox.showerror("Error", f"Prediction failed:\n{str(e)}")
        return

    for i in range(len(predictions)):
        result_label = labels[predictions[i]]
        text.insert(tk.END, f"Test DATA : {testData[i]} ===> PREDICTED AS {result_label}\n\n")

def graph():
    if not accuracy:
        messagebox.showerror("Error", "Run models first")
        return
    data = {
        'Algorithm': ["Naive Bayes", "Random Forest", "SVM", "XGBoost", "AdaBoost", "KNN"],
        'Accuracy': accuracy,
        'Precision': precision,
        'Recall': recall,
        'F1 Score': fscore
    }
    df = pd.DataFrame(data)
    df.set_index('Algorithm').plot(kind='bar')
    plt.title("Model Performance Comparison")
    plt.ylabel("Scores")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

# UI Buttons
font1 = ('times', 13, 'bold')
Label(main, text='Mitigating DDOS Attack In IOT Network Environment', bg='greenyellow', fg='dodger blue', font=('times', 16, 'bold'), height=3, width=120).place(x=0, y=5)
Button(main, text="Upload Dataset", command=uploadDataset, font=font1).place(x=50, y=550)
Button(main, text="Preprocess Dataset", command=preprocessDataset, font=font1).place(x=250, y=550)
Button(main, text="Run Naive Bayes", command=runNaiveBayes, font=font1).place(x=450, y=550)
Button(main, text="Run Random Forest", command=runRandomForest, font=font1).place(x=650, y=550)
Button(main, text="Run SVM", command=runSVM, font=font1).place(x=850, y=550)
Button(main, text="Run XGBoost", command=runXGBoost, font=font1).place(x=1050, y=550)
Button(main, text="Run AdaBoost", command=runAdaBoost, font=font1).place(x=50, y=600)
Button(main, text="Run KNN", command=runKNN, font=font1).place(x=250, y=600)
Button(main, text="Graph Comparison", command=graph, font=font1).place(x=450, y=600)
Button(main, text="Predict Attack", command=predict, font=font1).place(x=650, y=600)

main.config(bg='LightSkyBlue')
main.mainloop()
