import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from imblearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from joblib import dump


def ProcessCSVFile(csvFile):

    df = pd.read_csv(csvFile)

    X = df.iloc[:, :-1].values
    y = df.iloc[:, -1].values

    return X, y


csvFile = 'trimmed_train.csv'


print('Processing CSV File...')
X, y = ProcessCSVFile(csvFile)
print('Finished Processing CSV File')


columnsToEncode = [1, 2, 3]
encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
preprocessor = ColumnTransformer(transformers=[('cat', encoder, columnsToEncode)])


gradientBoostingClassifier = HistGradientBoostingClassifier(
    early_stopping=True,
    l2_regularization=1.1059430296617508e-10,
    learning_rate=0.6462545978214428,
    max_iter=64,
    max_leaf_nodes=36,
    min_samples_leaf=22,
    n_iter_no_change=5,
    random_state=1,
    validation_fraction=None,
    warm_start=True
)
model = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', gradientBoostingClassifier)])


print('Spliting into test and train sets...')
XTrain, XTest, yTrain, yTest = train_test_split(X, y, test_size=0.2, random_state=40, stratify=y)
print('Finished Spliting into test and train sets')


print('Fitting model...')
model.fit(XTrain, yTrain)
print('Finished Fitting model')


dump(model, 'GradientBoostingFile.pkl')


yPred = model.predict(XTest)


accuracy = accuracy_score(yTest, yPred)
print(f'Accuracy: {accuracy}')


precision = precision_score(yTest, yPred, average='weighted')
print(f'Precision: {precision}')


recall = recall_score(yTest, yPred, average='weighted')
print(f'Recall: {recall}')


f1 = f1_score(yTest, yPred, average='weighted')
print(f'F1-Score: {f1}')
