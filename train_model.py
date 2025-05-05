import pandas as pd
from sklearn.model_selection import train_test_split
from xgboost import XGBRegressor
from pickle import dump

# Load and preprocess data
df = pd.read_csv("insurance.csv")
df['sex'] = df['sex'].map({'male':0, 'female':1})
df['smoker'] = df['smoker'].map({'yes':1, 'no':0})
df['region'] = df['region'].map({'northwest':0, 'northeast':1, 'southeast':2, 'southwest':3})

# Prepare features and target
X = df.drop(['charges'], axis=1)
Y = df[['charges']]

# Train-test split
xtrain, xtest, ytrain, ytest = train_test_split(X, Y, test_size=0.2, random_state=42)

# Train model with all features
model = XGBRegressor(n_estimators=15, max_depth=3, gamma=0)
model.fit(xtrain, ytrain)

# Save model
dump(model, open('insurancemodelf_fullfeatures.pkl', 'wb'))

print("Model trained and saved with all 6 features")
