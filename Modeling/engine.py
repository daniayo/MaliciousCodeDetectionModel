import pandas as pd
import numpy as np
import joblib
from extract_ngram import NGRAM_features
import os


rf_model_ngram = joblib.load('rf_model_ngram.joblib')

ngram_columns = pd.read_csv('patterns.csv', header=0).columns

def extract_features_from_file(file_path, ngram_extractor, ngram_size=4):
    try:
        byte_code = ngram_extractor.get_opcodes(0, file_path)
        if not byte_code:
            return None
        grams = ngram_extractor.n_grams(ngram_size, byte_code, 0)
        return grams
    except Exception:
        return None 

def predict(file_path):

    ngram_extractor = NGRAM_features()
    ngram_size = 4 


    grams = extract_features_from_file(file_path, ngram_extractor, ngram_size)
    

    if grams is None:
        return "Malware"

    ngram_encoded = pd.get_dummies(pd.DataFrame([grams], columns=ngram_columns))


    missing_columns = set(ngram_columns) - set(ngram_encoded.columns)
    for column in missing_columns:
        ngram_encoded[column] = 0

    ngram_encoded = ngram_encoded[ngram_columns]

    ngram_encoded_filled = ngram_encoded.fillna(0)

    ngram_encoded_array = ngram_encoded_filled.to_numpy()

    try:
        prediction = rf_model_ngram.predict(ngram_encoded_array)
    except ValueError as e:
        print(f"[ERROR] Feature mismatch: {e}")
        return "Malware"

    if prediction == 1:
        return "Malware"
    else:
        return "Normal"

def process_files_in_directory(folder_path):

    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)

        if os.path.isfile(file_path):
            result = predict(file_path)
            print(f"File {file_path} is classified as {result}")

folder_path = '/home/ubuntu/test/'

process_files_in_directory(folder_path)

