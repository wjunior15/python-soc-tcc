import pandas as pd
import numpy as np
import keras
import tensorflow as tf
import config
import queries
import os
import pickle

def get_model_and_encoder():
    """
    Função que faz a importação dos modelos de RNA e encoder de dados.
        
    Returns:
        out_scaler (scaler): Modelo de scaler de dados pré-treinado.
        out_model (tf_model): Modelo pré-treinado do tensorflow.
    """
    
    #Linux path
    scaler_path = os.getcwd()+config.SCALER_PATH
    model_path = os.getcwd()+config.MODEL_PATH
    
    #Windows path
    if config.SYSTEM_NAME == 'Windows':
            scaler_path = config.PROJECT_PATH+config.SCALER_PATH.replace('/','\\')
            model_path = config.PROJECT_PATH+config.MODEL_PATH.replace('/','\\')
    
    out_scaler = pickle.load(open(scaler_path, 'rb'))
    out_model = keras.models.load_model(model_path)
    print(" --- Modelo TF e Scaler importados com sucesso!")
    
    return out_scaler, out_model
    
def get_model_data_format(in_dict_data, in_scaler):
    dt_data = pd.DataFrame([in_dict_data])
    dt_data.drop(['ID', 'ID PCAP', 'Label', 'Status'], axis=1, inplace=True)

    np_data = dt_data.to_numpy()
    return np_data
    
def get_predict_value(in_model, in_array):
    prediction = in_model.predict(in_array)
    prediction_argmax = np.argmax(prediction, axis=1)
    label = "BENIGN"
    if prediction_argmax[0] == 1:
        label = "MALIGN"
    return label

def main():
    try:        
        print("---- INICIA ANALYZE on",config.SYSTEM_NAME,"version",config.CODE_VERSION, "----")
        
        scaler, model = get_model_and_encoder()
        
        while 1:
            
            dict_data = queries.get_new_alert()
            id_alert = dict_data['ID']
            real_label = dict_data['Label']
            queries.update_alert_status(id_alert, "RUNNING")
            
            model_data = get_model_data_format(dict_data, scaler)
            predicted_label = get_predict_value(model, model_data)
            print("PREDICTED LABEL:",predicted_label," -- X -- REAL LABEL:",real_label)
            queries.update_alert_status(id_alert, predicted_label)
        
    except Exception as e:
        print("Erro na análise:", str(e))
        print("     ------- Traceback Completo do ERRO -------")
    
    except KeyboardInterrupt:
        print(" --- EXECUÇÃO INTERROMPIDA PELO USUÁRIO ---")

if __name__ == '__main__':
    main()
    