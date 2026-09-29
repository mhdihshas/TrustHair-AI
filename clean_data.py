import pandas as pd

print("Loading dataset...")
df = pd.read_csv('fake_job_postings.csv')

# 1. Fill missing text with an empty string so Python doesn't crash
# We use inplace=True to modify the dataset directly
df.fillna('', inplace=True)

# 2. Combine the most important text columns into one massive text block per job
print("Combining text columns...")
df['combined_text'] = df['title'] + " " + df['company_profile'] + " " + df['description'] + " " + df['requirements']

# 3. Let's look at the very first job's new combined text (first 500 characters)
print("\n--- New Combined Text (Job 1) ---")
print(df['combined_text'].iloc[0][:500]) 

# 4. Save this clean version to a new file so we don't ruin our original data
print("\nSaving clean dataset...")
df.to_csv('cleaned_job_postings.csv', index=False)
print("Saved as 'cleaned_job_postings.csv'!")