import streamlit as st
import pefile
import pandas as pd
import joblib

model = joblib.load('random_forest_model.pkl')

def extract_pe_features(filepath_or_bytes, filename="uploaded_file.exe"):
    """
    Extract PE header features from a PE file path or bytes.
    Returns a DataFrame with features for one file.
    """
    try:
        pe = pefile.PE(data=filepath_or_bytes)

        # Extract DOS Header fields
        dos_header_fields = [
            'e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc',
            'e_maxalloc', 'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs', 'e_lfarlc',
            'e_ovno', 'e_oemid', 'e_oeminfo', 'e_lfanew'
        ]
        dos_header = {field: getattr(pe.DOS_HEADER, field) for field in dos_header_fields}

        # Extract File Header fields
        file_header_fields = [
            'Machine', 'NumberOfSections', 'TimeDateStamp',
            'PointerToSymbolTable', 'NumberOfSymbols',
            'SizeOfOptionalHeader', 'Characteristics'
        ]
        file_header = {field: getattr(pe.FILE_HEADER, field) for field in file_header_fields}

        # Extract Optional Header fields
        optional_header_fields = [
            'Magic', 'MajorLinkerVersion', 'MinorLinkerVersion',
            'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData',
            'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase', 'SectionAlignment',
            'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
            'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion',
            'MinorSubsystemVersion', 'SizeOfHeaders', 'CheckSum', 'Subsystem',
            'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit',
            'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes'
        ]
        optional_header = {field: getattr(pe.OPTIONAL_HEADER, field) for field in optional_header_fields}

        # Extract Image Directory entries (all 16)
        image_directory = {}
        for i in range(16):  # 16 directories
            entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[i]
            image_directory[f"ImageDirectory_{i}_VirtualAddress"] = entry.VirtualAddress
            image_directory[f"ImageDirectory_{i}_Size"] = entry.Size

        # Combine all features
        all_features = {'filename': filename}
        all_features.update(dos_header)
        all_features.update(file_header)
        all_features.update(optional_header)
        all_features.update(image_directory)

        # Convert to DataFrame with single row
        df_features = pd.DataFrame([all_features])
        return df_features

    except pefile.PEFormatError:
        st.error(f"The uploaded file is not a valid PE file.")
    except Exception as e:
        st.error(f"Error processing file: {e}")

    return None

def predict_pe(features_df):
    X = features_df.drop(columns=['filename'])
    pred_prob = model.predict_proba(X)[:, 1]  # probability class 1
    threshold = 0.45
    pred_class = ["Benign", "Malicious"][pred_prob[0] >= threshold]
    return pred_class, pred_prob[0]

def main():
    st.title("PE Malware Classification")

    uploaded_file = st.file_uploader("Upload a Windows PE file (.exe, .dll)", type=["exe", "dll"])
    
    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        df = extract_pe_features(file_bytes, filename=uploaded_file.name)

        if df is not None:
            st.subheader("Extracted PE Header Features")
            st.dataframe(df)

            # Predict
            prediction, probability = predict_pe(df)
            st.subheader("Prediction")
            st.write(f"**Class:** {prediction}")
            st.write(f"**Malicious Probability:** {probability:.4f}")


if __name__ == "__main__":
    main()