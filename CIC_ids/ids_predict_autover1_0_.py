import numpy as np # linear algebra
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)
from tensorflow import keras 
from tensorflow.keras.models import load_model
import time
import os
import subprocess

model_path='./model/CICIDS2018_model-2.h5'
rule_template = "drop ip {src_ip} any -> $HOME_NET any (msg:\"Possible Attack Detected\";content:\"........\"; nocase; classtype:policy-violation; sid:{rule_sid}; rev:1;)"

class feature_extractor():
	def __init__(self, interface = "ens160", time_duration = "10s"):
		self.interface = interface
		self.collecting_duration=time_duration
		self.path=os.path.abspath(os.getcwd())
		self.pcap_file_name = "collecting_result.pcap"
		self.feature_file = "packet/feature1.csv"
	def get_feature(self):
		print("start getting packets and convert to features...")
		subprocess.run(["timeout", self.collecting_duration, "tcpdump","-i", self.interface,"-w", self.pcap_file_name])
		subprocess.run(["docker", "run", "--rm", "-v", self.path + ":/cicflowmeter", "cicflowmeter", "-f", self.pcap_file_name, "-c", self.feature_file])

class rule_updater():
	def __init__(self):
		self.model = load_model(model_path)
		self.file_path = "packet/feature2.csv"
		self.feature_extractor = feature_extractor()
		self.rule_path = "/var/lib/suricata/rules/local.rules"
		self.rule_sid = 2522900
		self.ip_label_pair = {}
	def feature_parsed(self):
		file = pd.read_csv(self.file_path)

		df_srcip=[]
		df_srcip.append(file["src_ip"])
		df_srcip = np.array(df_srcip)

		df_list = []
		file = file.drop(columns = ["src_ip","dst_ip","src_port","src_mac","dst_mac","timestamp", "protocol","psh_flag_cnt","init_fwd_win_byts","flow_byts_s","flow_pkts_s"], axis=1)
		df_list.append(file)

		del file
		df = pd.concat(df_list, axis=0, ignore_index=True)
		del df_list
		cleaned_data = df.dropna()
		del df
		X_test = cleaned_data.iloc[:, :].values
		X_test = np.expand_dims(X_test,axis=-1)
		del cleaned_data
		return df_srcip, X_test
	def predict_label(self, data):
		print("model is analyzing...")
		result = self.model.predict(data)
		result=np.array(result)
		#預測結果(機率)轉換成標籤(label)
		pred_label=[[] for i in range(len(result))]
		result=result.tolist()
		for i in range(len(result)):
			pred_label[i]=result[i].index(max(result[i]))
		result=np.array(result)
		return pred_label
	def generate_rules(self):
		print("----------------"+"start generateing rules"+"----------------")
		rules = []
		# self.feature_extractor.get_feature()
		src_ip, data_test = self.feature_parsed()
		data_label = self.predict_label(data_test)
		for i in range(len(data_label)):
			if src_ip[0][i] in self.ip_label_pair:
				if self.ip_label_pair[src_ip[0][i]] < data_label[i] :
					self.ip_label_pair[src_ip[0][i]] = data_label[i]	
			else:
				self.ip_label_pair[src_ip[0][i]] = data_label[i]
		for key, value in self.ip_label_pair.items():
			if int(value) != 0:
				new_rule = rule_template.format(src_ip = key, rule_sid = self.rule_sid)
				rules.append(new_rule)
				print("rules "+"ip: {key} type{value}\n".format(key= key, value = value))
				self.rule_sid  = self.rule_sid + 1
		print("----------------"+"finish generateing rules"+"----------------")
		return rules
	def update_rules(self, rules):
		print("----------------"+"updating rules"+"----------------")
		print("updating rule")
		subprocess.run(["systemctl", "stop", "suricata"])
		time.sleep(10)
		f = open(self.rule_path, "w+")
		for rule in rules:
			f.write("\n"+rule)	
		print("----------------"+"finish updating rules"+"----------------")
		subprocess.run(["systemctl", "restart", "suricata"])		


def main():
	updater = rule_updater()
	rules = updater.generate_rules()
	updater.update_rules(rules)
	# while(1):
	# 	rules = updater.generate_rules()
	# 	updater.update_rules(rules)
	# 	sleep(10)

if __name__ == "__main__":
	main()
### below is the original code ###

# # 載入模型
# model = load_model(model_path)

# packet_floder='./packet/'

# for i in range(1,4):
# 	#path & load data
# 	s='feature'+str(i)+'.csv'
# 	s=os.path.join(packet_floder,s)
# 	file = pd.read_csv(s)
# 	#獲取來源ip列表
# 	df_srcip=[]
# 	df_srcip.append(file["src_ip"])
# 	df_srcip=np.array(df_srcip)
# 	#drop不要的特徵
	
# 	file = file.drop(columns = ["src_ip","dst_ip","src_port","src_mac","dst_mac","timestamp", "protocol","psh_flag_cnt","init_fwd_win_byts","flow_byts_s","flow_pkts_s"], axis=1)
	
# 	#處理資料型態成為input
# 	df_list = []
# 	df_list.append(file)
# 	del file
# 	df = pd.concat(df_list, axis=0, ignore_index=True)
# 	del df_list
# 	cleaned_data = df.dropna()
# 	del df
# 	X_test = cleaned_data.iloc[:, :].values
# 	X_test = np.expand_dims(X_test,axis=-1)
# 	del cleaned_data
# 	#模型預測
# 	print('model is analyzing...')
# 	result = model.predict(X_test)
# 	result=np.array(result)
# 	#預測結果(機率)轉換成標籤(label)
# 	pred_label=[[] for i in range(len(result))]
# 	result=result.tolist()
# 	for i in range(len(result)):
# 		pred_label[i]=result[i].index(max(result[i]))
# 	result=np.array(result)

# 	#output結果:
# 	for i in range(len(result)):
# 		print(i,".","ip:",df_srcip[0][i]," label:",pred_label[i])
	
# 	print('complete.And prepare starting next run.\n')
	
# 	#p.s釋放空間
# 	del df_srcip
# 	del X_test
# 	del result
# 	del pred_label
# 	#緩衝時間
# 	time.sleep(5)


# # 刪除既有模型變數
# del model
