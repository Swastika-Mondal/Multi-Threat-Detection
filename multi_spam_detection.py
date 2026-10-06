import warnings
warnings.filterwarnings('ignore')
import gradio as gr
import joblib
import re
import english_stopwords as es

# stop words 
stopwords = es.ENGLISH_STOP_WORDS


# spam email detection
email_vect = joblib.load("models/spam_email_model/spam_email_tfid_vect.pkl")
email_model = joblib.load("models/spam_email_model/spam_email_model.pkl")

# cyber bullying text detection
cyber_bullying_vect = joblib.load("models/cyber_bullying_model/cyber_bullying_tfid_vect.pkl")
cyber_bullying_model = joblib.load("models/cyber_bullying_model/cyber_bullyingl_model.pkl")

# network traffic detection
rtiot_model = joblib.load("models/rtiot_model/RT_IoT_model.pkl")

# spam email detection function
def spam_email_detection(input_text):
    text = email_vect.transform([input_text])
    if email_model.predict(text)[0]:
        return 'Spam Email detected'.title()
    else:
        return 'not a spam email'.title()

# cyber bullying text detection
def cyberbullying_detection(input_text):   
    text = re.sub(r'http\S+', '', input_text)  # Remove URLs
    text = re.sub(r'@\w+', '', text)     # Remove mentions
    text = re.sub(r'#\w+', '', text)     # Remove hashtags
    text = re.sub(r'\d+', '', text)      # Remove numbers
    text = text.lower()                  # Convert to lowercase
    text = text.split()
    text = [word for word in text if word not in stopwords]
    text = ' '.join(text)

    text = cyber_bullying_vect.transform([input_text])
    if cyber_bullying_model.predict(text)[0]:
        return 'Cyber bullying text detected'.title()
    else:
        return 'not a Cyber bullying text'.title()

# twitter sentiment analysis
def network_traffic_analysis(*inputs):
    if '' in inputs:
        return
    (id_resp_p, proto, service, fwd_header_size_tot, 
     fwd_header_size_min, fwd_header_size_max, flow_SYN_flag_count, 
     fwd_PSH_flag_count, fwd_URG_flag_count, fwd_pkts_payload_min, 
     fwd_pkts_payload_max, fwd_pkts_payload_tot, fwd_pkts_payload_avg, 
     bwd_pkts_payload_avg, flow_pkts_payload_max, flow_pkts_payload_tot, 
     flow_pkts_payload_avg, fwd_iat_min, fwd_iat_max, fwd_iat_std, 
     flow_iat_min, flow_iat_max, flow_iat_tot, flow_iat_avg,
     flow_iat_std, fwd_subflow_bytes, active_min, active_max,
     active_avg, idle_min, idle_max, idle_avg, fwd_init_window_size, 
     bwd_init_window_size, fwd_last_window_size) = inputs
    
    proto_encode = {'icmp': 0, 'tcp': 1, 'udp': 2}
    service_encode = {'-': 0, 'dhcp': 1, 'dns': 2, 'http': 3, 'irc': 4, 'mqtt': 5, 'ntp': 6, 'radius': 7, 'ssh': 8, 'ssl': 9}
    attack_type = {0: 'ARP_poisioning', 1: 'DDOS_Slowloris', 2: 'DOS_SYN_Hping', 3: 'MQTT_Publish', 4: 'Metasploit_Brute_Force_SSH',
                   5: 'NMAP_FIN_SCAN', 6: 'NMAP_OS_DETECTION', 7: 'NMAP_TCP_scan', 8: 'NMAP_UDP_SCAN', 9: 'NMAP_XMAS_TREE_SCAN',
                   10: 'Thing_Speak', 11: 'Wipro_bulb'}
    
    id_resp_p = float(id_resp_p)
    proto = proto_encode.get(proto.lower().strip(), 0)
    service = service_encode.get(service.lower().strip(), 0)
    fwd_header_size_tot = float(fwd_header_size_tot)
    fwd_header_size_min = float(fwd_header_size_min)
    fwd_header_size_max = float(fwd_header_size_max)
    flow_SYN_flag_count = float(flow_SYN_flag_count)
    fwd_PSH_flag_count = float(fwd_PSH_flag_count)
    fwd_URG_flag_count = float(fwd_URG_flag_count)
    fwd_pkts_payload_min = float(fwd_pkts_payload_min)
    fwd_pkts_payload_max = float(fwd_pkts_payload_max)
    fwd_pkts_payload_tot = float(fwd_pkts_payload_tot)
    fwd_pkts_payload_avg = float(fwd_pkts_payload_avg)
    bwd_pkts_payload_avg = float(bwd_pkts_payload_avg)
    flow_pkts_payload_max = float(flow_pkts_payload_max)
    flow_pkts_payload_tot = float(flow_pkts_payload_tot)
    flow_pkts_payload_avg = float(flow_pkts_payload_avg)
    fwd_iat_min = float(fwd_iat_min)
    fwd_iat_max = float(fwd_iat_max)
    fwd_iat_std = float(fwd_iat_std)
    flow_iat_min = float(flow_iat_min)
    flow_iat_max = float(flow_iat_max)
    flow_iat_tot = float(flow_iat_tot)
    flow_iat_avg = float(flow_iat_avg)
    flow_iat_std = float(flow_iat_std)
    fwd_subflow_bytes = float(fwd_subflow_bytes)
    active_min = float(active_min)
    active_max = float(active_max)
    active_avg = float(active_avg)
    idle_min = float(idle_min)
    idle_max = float(idle_max)
    idle_avg = float(idle_avg)
    fwd_init_window_size = float(fwd_init_window_size)
    bwd_init_window_size = float(bwd_init_window_size)
    fwd_last_window_size = float(fwd_last_window_size)
    
    res = rtiot_model.predict([[id_resp_p, proto, service, fwd_header_size_tot, 
     fwd_header_size_min, fwd_header_size_max, flow_SYN_flag_count, 
     fwd_PSH_flag_count, fwd_URG_flag_count, fwd_pkts_payload_min, 
     fwd_pkts_payload_max, fwd_pkts_payload_tot, fwd_pkts_payload_avg, 
     bwd_pkts_payload_avg, flow_pkts_payload_max, flow_pkts_payload_tot, 
     flow_pkts_payload_avg, fwd_iat_min, fwd_iat_max, fwd_iat_std, 
     flow_iat_min, flow_iat_max, flow_iat_tot, flow_iat_avg,
     flow_iat_std, fwd_subflow_bytes, active_min, active_max,
     active_avg, idle_min, idle_max, idle_avg, fwd_init_window_size, 
     bwd_init_window_size, fwd_last_window_size]])
    
    attack = attack_type.get(res[0], 0)
    
    
    return f"This attack falling under: {attack}"


with gr.Blocks() as multimodel:
    gr.Markdown("<h1 align='center'>Integration of many ML classification in one frame<h1>".title(), elem_id="title")
    
    with gr.Row():
        spam_checkbox = gr.Checkbox(label="Spam email detection")
        cyberbullying_checkbox = gr.Checkbox(label="Cyberbullying detection")
        rtiot_checkbox = gr.Checkbox(label="Network Traffic Analysis")
    
    with gr.Row(visible=False) as spam_row:
        with gr.Column():
            gr.Markdown('## Spam email detection : ')
            spam_input = gr.Textbox(label="Input text", interactive=True)
            spam_output = gr.Textbox(label="Output text", interactive=True)
            gr.Interface(spam_email_detection, spam_input, spam_output, live=True)
        
    with gr.Row(visible=False) as cyberbullying_row:
        with gr.Column():
            gr.Markdown('## Cyberbullying detection : ')
            cyberbullying_input = gr.Textbox(label="Input text", interactive=True)
            cyberbullying_output = gr.Textbox(label="Output text", interactive=True)
            gr.Interface(cyberbullying_detection, cyberbullying_input, cyberbullying_output, live=True)
    
    with gr.Row(visible=False) as rtiot_row:
        with gr.Column():
            gr.Markdown('## Network Traffic Analysis:')
            
            inputs = []
            input_labels = ['id.resp_p', 'proto', 'service', 'fwd_header_size_tot', 
                            'fwd_header_size_min', 'fwd_header_size_max', 'flow_SYN_flag_count', 
                            'fwd_PSH_flag_count', 'fwd_URG_flag_count', 'fwd_pkts_payload.min', 
                            'fwd_pkts_payload.max', 'fwd_pkts_payload.tot', 'fwd_pkts_payload.avg', 
                            'bwd_pkts_payload.avg', 'flow_pkts_payload.max', 'flow_pkts_payload.tot', 
                            'flow_pkts_payload.avg', 'fwd_iat.min', 'fwd_iat.max', 'fwd_iat.std', 
                            'flow_iat.min', 'flow_iat.max', 'flow_iat.tot', 'flow_iat.avg', 
                            'flow_iat.std', 'fwd_subflow_bytes', 'active.min', 'active.max', 
                            'active.avg', 'idle.min', 'idle.max', 'idle.avg', 'fwd_init_window_size', 
                            'bwd_init_window_size', 'fwd_last_window_size']
            
            for label in input_labels:
                inputs.append(gr.Textbox(label=label, interactive=True))
            
            output_text = gr.Textbox(label="Output", interactive=True)

            gr.Interface(network_traffic_analysis, inputs, output_text, live=True)

    def update_visibility(spam, cyberbullying, rtiot):
        return {
            spam_row: gr.update(visible=spam),
            cyberbullying_row: gr.update(visible=cyberbullying),
            rtiot_row: gr.update(visible=rtiot),
        }

    checkbox_group = [spam_checkbox, cyberbullying_checkbox, rtiot_checkbox]
    for checkbox in checkbox_group:
        checkbox.change(
            update_visibility,
            inputs=[spam_checkbox, cyberbullying_checkbox, rtiot_checkbox],
            outputs=[spam_row, cyberbullying_row, rtiot_row],
        )

multimodel.launch(server_port=4747)