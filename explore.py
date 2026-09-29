import pandas as pd

# 1. Load the dataset into a Pandas "DataFrame"
print("Loading dataset...")
df = pd.read_csv('fake_job_postings.csv')

# 2. Check the size of the dataset (Rows, Columns)
print("\n--- Dataset Size ---")
print(f"Total Rows: {df.shape[0]}")
print(f"Total Columns: {df.shape[1]}")

# 3. List the column names so we know what information we have
print("\n--- Column Names ---")
print(df.columns.tolist())

# 4. Count how many jobs are Real (0) vs Fake (1)
print("\n--- Real vs Fake Job Count ---")
print(df['fraudulent'].value_counts())

# 5. Look at the first 3 rows of the actual job descriptions
print("\n--- Sample Job Descriptions ---")
print(df['description'].head(3))