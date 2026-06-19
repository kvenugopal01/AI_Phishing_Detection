# simple machine learning script to train our classifier model
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

# 1. Load data from CSV file
data_frame = pd.read_csv("dataset/dataset.csv")

# 2. Clean data - drop the index column that is not needed
data_frame = data_frame.drop("index", axis=1)

# 3. Separate features (X) and target/result label (y)
X = data_frame.drop("Result", axis=1)
y = data_frame["Result"]

# 4. Split data into train and test groups (80/20 split)
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# 5. Initialize RandomForestClassifier with 100 trees
model_classifier = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

# 6. Fit the training data into model
model_classifier.fit(X_train, y_train)

# 7. Make predictions on test dataset
predictions = model_classifier.predict(X_test)

# 8. Check classifier performance
acc = accuracy_score(y_test, predictions)
print("Model accuracy is:", acc * 100)

print("\n--- Model Classification Report ---")
print(classification_report(y_test, predictions))

# 9. Save output pickle file to disk
joblib.dump(model_classifier, "phishing_model.pkl")
print("Model has been saved to phishing_model.pkl successfully!")
