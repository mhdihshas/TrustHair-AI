import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# 1. Load the Cleaned Data
print("Loading cleaned dataset...")
df = pd.read_csv('cleaned_job_postings.csv')

# Ensure there are absolutely no empty rows left over
df.dropna(subset=['combined_text', 'fraudulent'], inplace=True)

# 2. Split Data: 80% for Training, 20% for Testing
# We hold back 20% so we can test the AI on jobs it has NEVER seen before.
print("Splitting data into Training and Testing sets...")
X = df['combined_text']
y = df['fraudulent']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 3. Vectorize the Text (The TF-IDF Magic)
print("Converting text to numbers using TF-IDF...")
# We limit to the top 5,000 most important words to save memory
vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)

# We 'fit' (learn the vocabulary) and 'transform' (convert to numbers) the training data
X_train_vectorized = vectorizer.fit_transform(X_train)
# We ONLY 'transform' the test data so the AI doesn't cheat by looking at the test vocabulary
X_test_vectorized = vectorizer.transform(X_test)

# 4. Train the AI Model
print("Training the Logistic Regression model...")
# class_weight='balanced' forces the AI to pay extra attention to the rare fake jobs!
model = LogisticRegression(class_weight='balanced', max_iter=1000)
model.fit(X_train_vectorized, y_train)

# 5. Test the AI and Print the Results
print("\n--- Model Evaluation ---")
y_pred = model.predict(X_test_vectorized)

print("\nConfusion Matrix (Real vs Fake predictions):")
print(confusion_matrix(y_test, y_pred))

print("\nDetailed Accuracy Report:")
print(classification_report(y_test, y_pred))

# 6. Save the Brain to a File
print("\nSaving the model and vectorizer...")
joblib.dump(model, 'scam_model.pkl')
joblib.dump(vectorizer, 'text_vectorizer.pkl')
print("Complete! Files saved as scam_model.pkl and text_vectorizer.pkl.")