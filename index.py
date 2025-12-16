import numpy as np
import pandas as pd
import os


from sklearn.model_selection import train_test_split
# to encode categories
from sklearn.preprocessing import OneHotEncoder
#encode  the labels in my case the class (A/N)
from sklearn.preprocessing import LabelEncoder


#For the model of Decission Tree
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.tree import export_text
from sklearn.metrics import classification_report



#my dictionary fo columns i hope that my fucked up logique will work
column_mapping = { 
    # IPs
    'src_ip': [' Source IP', 'Src IP', 'src_ip', 'src ip'],
    'dst_ip': [' Destination IP', 'Dst IP', 'dst_ip', 'dst ip'],

    # Ports
    'src_port': [' Source Port', 'Src Port', 'src_port', 'src port'],
    'dst_port': [' Destination Port', 'Dst Port', 'dst_port', 'dst port'],

    # Protocol
    'protocol': [' Protocol', 'protocol'],

    # Packet / Flow features
    'flow_duration': [' Flow Duration', 'flow_duration', 'Flow Duration'],
    'total_fwd_packets': [' Total Fwd Packets', 'Total Fwd Packets', 'Fwd Packets'],
    'total_bwd_packets': [' Total Backward Packets', 'Total Backward Packets', 'Bwd Packets'],
    'total_length_fwd': ['Total Length of Fwd Packets', 'Total Length Fwd Packets'],
    'total_length_bwd': [' Total Length of Bwd Packets', 'Total Length Bwd Packets'],
    'fwd_pkt_len_max': [' Fwd Packet Length Max', 'Fwd Packet Length Max'],
    'fwd_pkt_len_min': [' Fwd Packet Length Min', 'Fwd Packet Length Min'],
    'fwd_pkt_len_mean': [' Fwd Packet Length Mean', 'Fwd Packet Length Mean'],
    'fwd_pkt_len_std': [' Fwd Packet Length Std', 'Fwd Packet Length Std'],
    'bwd_pkt_len_max': ['Bwd Packet Length Max', ' Bwd Packet Length Max'],
    'bwd_pkt_len_min': [' Bwd Packet Length Min', 'Bwd Packet Length Min'],
    'bwd_pkt_len_mean': [' Bwd Packet Length Mean', 'Bwd Packet Length Mean'],
    'bwd_pkt_len_std': [' Bwd Packet Length Std', 'Bwd Packet Length Std'],
    'flow_bytes_per_s': ['Flow Bytes/s', ' Flow Bytes/s'],
    'flow_packets_per_s': [' Flow Packets/s', 'Fwd Packets/s', ' Bwd Packets/s'],
    
    # IAT (Inter-arrival times)
    'flow_iat_mean': [' Flow IAT Mean', 'Flow IAT Mean'],
    'flow_iat_std': [' Flow IAT Std', 'Flow IAT Std'],
    'flow_iat_max': [' Flow IAT Max', 'Flow IAT Max'],
    'flow_iat_min': [' Flow IAT Min', 'Flow IAT Min'],
    'fwd_iat_total': ['Fwd IAT Total'],
    'fwd_iat_mean': [' Fwd IAT Mean'],
    'fwd_iat_std': [' Fwd IAT Std'],
    'fwd_iat_max': [' Fwd IAT Max'],
    'fwd_iat_min': [' Fwd IAT Min'],
    'bwd_iat_total': ['Bwd IAT Total'],
    'bwd_iat_mean': [' Bwd IAT Mean'],
    'bwd_iat_std': [' Bwd IAT Std'],
    'bwd_iat_max': [' Bwd IAT Max'],
    'bwd_iat_min': [' Bwd IAT Min'],

    # Flags
    'fwd_psh_flags': ['Fwd PSH Flags', ' Fwd PSH Flags'],
    'bwd_psh_flags': [' Bwd PSH Flags', 'Bwd PSH Flags'],
    'fwd_urg_flags': [' Fwd URG Flags', 'Fwd URG Flags'],
    'bwd_urg_flags': [' Bwd URG Flags', 'Bwd URG Flags'],
    'fin_flag_count': ['FIN Flag Count'],
    'syn_flag_count': [' SYN Flag Count', 'SYN Flag Count'],
    'rst_flag_count': [' RST Flag Count', 'RST Flag Count'],
    'psh_flag_count': [' PSH Flag Count', 'PSH Flag Count'],
    'ack_flag_count': [' ACK Flag Count', 'ACK Flag Count'],
    'urg_flag_count': [' URG Flag Count', 'URG Flag Count'],

    # Packet size & flow statistics
    'avg_packet_size': [' Average Packet Size', 'Packet Length Mean'],
    'packet_len_std': [' Packet Length Std'],
    'packet_len_var': [' Packet Length Variance'],

    # Other metrics
    'label': [' Label', 'Attack', 'Class'],
    'flow_id': ['Flow ID'],
    'timestamp': [' Timestamp', 'Timestamp'],
    'active_mean': ['Active Mean', ' Active Mean'],
    'active_std': [' Active Std'],
    'idle_mean': ['Idle Mean', ' Idle Mean'],
    'idle_std': [' Idle Std']
}


# List all files in dirs and subdirs
def get_all_files(root_dir):
    all_files = []
    if not os.path.exists(root_dir):
        print(f"Directory {root_dir} does not exist!")
        return all_files
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    print(f"Found {len(all_files)} files in {root_dir} and subdirectories")
    return all_files


# Sort files by type
def sort_files(files):
    csv_array_files = []
    text_array_files = []
    log_array_files = []
    for file in files:
        if file.endswith('.csv'):
            csv_array_files.append(file)
        elif file.endswith('.txt') or file.endswith('.arff'):
            text_array_files.append(file)
        elif file.endswith('.log'):
            log_array_files.append(file)
    return csv_array_files, text_array_files, log_array_files


# Read CSV in chunks and store in map(i found the encoding issue so i just tested to fix it )
def open_csv_files(csv_files):
    chunk_size = 1000
    file_map = {}
    
    for file in csv_files:
        chunks = [] 
        try:
            for chunk in pd.read_csv(file, chunksize=chunk_size, encoding='utf-8'):
                chunks.append(chunk)
        except UnicodeDecodeError:
            for chunk in pd.read_csv(file, chunksize=chunk_size, encoding='latin1'):
                chunks.append(chunk)
        except Exception as e:
            print(f"Error reading file {file}: {e}")
            continue
        if chunks:
            file_map[file] = chunks
            print(f"Loaded {len(chunks)} chunks for file {file}")
        else:
            print(f"No chunks loaded for file {file}")
    return file_map

#function to open text files
def open_text_files(text_files):
   attributes = []
   lines_whitout_attribute = []
   for file in text_files:
       with open(file,'r') as f:
           for line in f:
               
               if not line or line.startswith('%'):
                   continue
               else:
                   if line.startswith("@attribute"):
                       current_line=line.split(' ')[1]
                       if current_line not in attributes:
                           attributes.append(current_line)
                     
                   else:
                       lines_whitout_attribute.append(line.strip())
                       
   return attributes,lines_whitout_attribute

#handle csv files chuks from my map 
def unify_chunks_in_one_dataframe_csv(csv_file_map):            
    all_chunks=[]  #store all chunks of all files 
    for chunks in csv_file_map.values():
        all_chunks.extend(chunks)
    full_df=pd.concat(all_chunks,ignore_index=True)
    full_df.to_csv("./Results/csv_result.csv",index=False)
    return full_df



def create_csv_from_attributes_text(attributes, lines, csv_file=None, delimiter=','):
    # Split each line into a list of values
    rows = []
    for line in lines:
        row = line.split(delimiter)
        rows.append(row)
        
    df = pd.DataFrame(rows, columns=attributes)
    df.to_csv(csv_file, index=False, sep=delimiter)
    
    return df



#this function will unify all the data in one data frame 
def UnifyData(final_csv_dataframe,final_text_dataframe):
    final_dataframe= pd.concat([final_csv_dataframe,final_text_dataframe],ignore_index=True)
    print("Generating your final data set please wait this proccess will take a while....^-^")
    final_dataframe.to_csv("./Results/final_results.csv")
    return final_dataframe


#function to open log files (for later)
# def open_log_files(log_files):
#     pass

#clearning the data from my final csv file  and  extract the columns and place the values in there correct values
def preProcessing(final_file, dictionary_of_final_features):
    chunk_size = 500
    processed_chunks = []

    reverse_map = {}
    for canonical_name, variants in dictionary_of_final_features.items():
        for v in variants:
            reverse_map[v.strip().lower()] = canonical_name

    try:
        for chunk in pd.read_csv(final_file, chunksize=chunk_size):

            chunk.columns = [col.strip().lower() for col in chunk.columns]

            rename_dict = {}
            for col in chunk.columns:
                if col in reverse_map:
                    rename_dict[col] = reverse_map[col]

            chunk = chunk.rename(columns=rename_dict)

            expected_features = list(dictionary_of_final_features.keys())
            chunk = chunk[[c for c in chunk.columns if c in expected_features]]

            processed_chunks.append(chunk)

        if not processed_chunks:
            print("No valid data found after preprocessing.")
            return None

        final_df = pd.concat(processed_chunks, ignore_index=True)

       
        for col in expected_features:
            if col not in final_df.columns:
                final_df[col] = np.nan

       
        final_df.to_csv("./Results/final_preprocessed.csv", index=False)
        print("Renaming and handling columns with  correct values completed successfully.")

        return final_df

    except Exception as e:
        print(f"Error during preprocessing of {final_file}: {e}")
        return None
    




# this part i didnt code it i get it from gpt becuase when i did it solo i needed 25 terabite of ram so my shit can work fuck that
def encode_and_prepare_for_ml(preprocessed_csv):
    df = pd.read_csv(preprocessed_csv)

    if 'label' not in df.columns:
        raise ValueError("Label column not found")

    label_encoder = LabelEncoder()
    df['label'] = label_encoder.fit_transform(df['label'].astype(str))
    print("\nLabel Encoding:")
    for cls, idx in zip(label_encoder.classes_, range(len(label_encoder.classes_))):
        print(f"{cls} -> {idx}")

    high_card_cols = ['src_ip', 'dst_ip', 'flow_id', 'timestamp']
    for col in high_card_cols:
        if col in df.columns:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            print(f"Label-encoded column: {col}")

    low_card_cols = ['protocol']
    for col in low_card_cols:
        if col in df.columns:
            ohe = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
            encoded = ohe.fit_transform(df[[col]].astype(str))
            df_encoded = pd.DataFrame(encoded, columns=ohe.get_feature_names_out([col]))
            df = pd.concat([df.drop(columns=[col]), df_encoded], axis=1)
            print(f"One-Hot encoded column: {col}")

    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

    X = df.drop(columns=['label'])
    y = df['label']

    return X, y



def decision_tree_pattern_generator(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        stratify=y,
        random_state=42
    )

    tree = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )

    tree.fit(X_train, y_train)
    rules = export_text(tree, feature_names=list(X.columns))
    print("\nDecision Tree Evaluation:\n")
    print(classification_report(y_test, tree.predict(X_test)))



    print("\n--- GENERATED PATTERNS ---\n")
    print(rules)

    return tree

    


def main():
    files = get_all_files('./Data')
    csv_array_files, text_array_files, log_array_files = sort_files(files)

     #opening and handling csv files (just for testing)
     
    csv_file_map = open_csv_files(csv_array_files)
    if csv_file_map:
        full_df = unify_chunks_in_one_dataframe_csv(csv_file_map)
        print(full_df.columns)
        print(full_df)
    else:
        print("No CSV files loaded successfully.")
        
     #opening and handling text files (just for testing)
    if text_array_files:
        attributes,text_lines_whitout_attribute =open_text_files(text_array_files)
        print(f'They are {len(attributes)} attributes')
        print(f'They are {len(text_lines_whitout_attribute)} rows')
        create_csv_from_attributes_text(attributes,text_lines_whitout_attribute,"./Results/results_text.csv")
    else:
        print("No text files loaded successfully.")
    
    
    #merging to All files into One
    if csv_file_map and text_array_files:
        final_csv_dataframe = pd.read_csv("./Results/csv_result.csv")
        final_text_dataframe = pd.read_csv("./Results/results_text.csv")
        final_dataframe = UnifyData(final_csv_dataframe,final_text_dataframe)
        print(final_dataframe.columns)
        print(final_dataframe)
        
        #preProccessing part
        final_preprocessed = preProcessing(
            "./Results/final_results.csv",
            column_mapping
        )

        #Ml part (Decission tree)
        if final_preprocessed is not None:
            print("Preprocessing completed.")
            X, y = encode_and_prepare_for_ml("./Results/final_preprocessed.csv")

            tree = decision_tree_pattern_generator(X, y)

        
        
        
    else:
        print("No CSV or text files loaded successfully.")

    #mapping and handling the final data set (USE REVERCE MAP  YA ALI NI PRESQUE RIGLT KOLCH)
    

#this shit from django that i never understoood but still doing it so nban 9atal
if __name__ =="__main__":
    main()
