import sys, os, time 
import json, re
import collections
import threading
import traceback
import pandas
import numpy
import MySQLdb
import optparse
from keras.models import Sequential, load_model
from keras.preprocessing import sequence
from keras.preprocessing.text import Tokenizer
from collections import OrderedDict


pA = re.compile('--[\d,a,b,c,d,e,f]{8}-A--')
pB = re.compile('--[\d,a,b,c,d,e,f]{8}-B--')
pC = re.compile('--[\d,a,b,c,d,e,f]{8}-C--')
pF = re.compile('--[\d,a,b,c,d,e,f]{8}-F--')
pH = re.compile('--[\d,a,b,c,d,e,f]{8}-H--')
pI = re.compile('--[\d,a,b,c,d,e,f]{8}-I--')
pZ = re.compile('--[\d,a,b,c,d,e,f]{8}-Z--')

NO_PAYLOAD = 0 
C_PAYLOAD = 1 
I_PAYLOAD = 2 

DB_HOST = 'localhost'
DB_NAME = 'adminlte_db'
DB_USER = 'adminlte'
DB_PWD = 'admin@123'
DB_TABLE = 'log_loaded'

g_query_queue = collections.deque([])
g_read_log_thread = None
g_except_event = False 
class DB_Connector():
	def __init__(self, host, user, password, dbname):
		self.connector = MySQLdb.connect(host, user, password, dbname)
		self.cursor = self.connector.cursor()
	def insert(self, data, table):
		if len(data) != 3:
			return False
		sql = "INSERT INTO %s(content, modsec_label, lstm_label, status)\
				 VALUES ('%s', %d, %d, 0) " % (table, data[0], data[1], data[2])
		print sql 
		try :
			self.cursor.execute(sql)
			self.connector.commit()
		except:
			self.connector.rollback()
			return False 
		return True 

class ModSecAuditLog :
	def __init__(self, A, B, C, F, H, I) :
		self.A = A 
		self.B = B 
		self.C = C		# list [ [name,value] or/and [name,filename,start_point, end_point] ]
		self.F = F
		self.H = H
		self.I = I 
	
	def display(self):
		print "A: ", self.A 
		#print "B: ", self.B 
		for line in self.B:
			print line 
		print "lenC: ", len(self.C)
		print self.C
		print "boundary: ", self.getBoundary()
		
	def getMethod(self):
		line = self.B[0]
		return line.split(' ')[0] 
		
	def getPayloadType(self):
		if len(self.C) != 0 :
			return C_PAYLOAD 
		elif len(self.I) != 0:
			return I_PAYLOAD
		return NO_PAYLOAD 

	# query only 
	def get_lstm_request(self):
		request = self.B[0].rstrip()

		if self.getPayloadType() == I_PAYLOAD:
			for line in self.I:
				request += '#' + line.rstrip()
		elif self.getPayloadType() == C_PAYLOAD:
			for line in self.C:
				request += '#' + line.rstrip()
		return request	


def signal(line):
	if pA.match(line) :
		return ('A',) 
	elif pB.match(line):
		return ('B',) 
	elif pF.match(line):
		return ('F',)
	elif pH.match(line):
		return ('H',)
	elif pC.match(line):
		return ('C',)
	elif pI.match(line):
		return ('I',)
	elif pZ.match(line):
		return ('Z', pZ.findall(line)[0]) 
	else :
		return None 

class Read_Log_Thread(threading.Thread):
	
	def __init__(self, log_file):
		super(Read_Log_Thread, self).__init__()
		self._stop_event = threading.Event()
		self.log_file = log_file
	
	def stop(self):
		self._stop_event.set()
	
	def run(self):
		global g_query_queue
		global g_except_event 
		with open(self.log_file, 'r') as f:
			A = []
			B = []
			C = []
			F = []
			H = []
			I = []
			line = f.readline()
			sig = signal(line)
			
			while True:
				#line = f.readline().rstrip()	# find first header (A header)
				#headerA = pA.findall(line)

				if not sig :
					sig = signal(f.readline())
					if not sig:
						continue
				elif sig[0] == 'A' :
					A = []
					while True:
						line = f.readline()
						sig = signal(line)
						if sig :
							break 
						A.append(line)
				elif sig[0] == 'B' :
					B = [] 
					while True:
						line = f.readline()
						sig = signal(line)
						if sig :
							break 
						B.append(line)
						
				elif sig[0] == 'C' :
					C = []
					while True:
						line = f.readline()
						sig = signal(line)
						if sig :
							break 
						C.append(line)
				elif sig[0] == 'I' :  
					I = []
					while True:
						line = f.readline()
						sig = signal(line)
						if sig : 
							break 
						I.append(line)
				elif sig[0] == 'F':
					F = []
					while True :
						line = f.readline()
						sig = signal(line)
						if sig :
							break 
						F.append(line.rstrip())
				elif sig[0] == 'H':
					H = []
					while True:
						line = f.readline()
						sig = signal(line)
						if sig :
							break 
						H.append(line)
				elif sig[0] == 'Z':
					log = ModSecAuditLog(A,B,C,F,H,I)
					request = log.get_lstm_request() # lstm-train format
					if request == '':
						print "request = null"
						return
					H_count = 0
					modsec_label = 0 
					for line in log.H :
						if line.find('Message') == 0:
							H_count += 1
						if H_count == 2:
							modsec_label = 1 
					#print H_count
					if H_count == 1:		# in case 1 rule CRS match and break (no other rule excute)
						if log.H[0].find('id "1010000"') == -1 :
							modsec_label = 1

					g_query_queue.append([request, modsec_label])
					#print "==>\n", request, "\n<=="
					A = []
					B = []
					C = []
					F = []
					H = []
					I = []
					while True :
						#line = f.readline()
						#if len(line) == 0:
							#print "Line207/request_loader.py --------> EOF"
							#print "Edit here to make it run infinite"
							#return 
						#	continue
						sig = signal(f.readline())
						if sig :
							break 
			
		return 



def predict_loop(csv_file):
    global g_query_queue
    global g_read_log_thread	
    # Loading processed word dictionary into keras Tokenizer would be better
    dataframe = pandas.read_csv(csv_file, engine='python', quotechar='|', header=None)
    dataset = dataframe.values

    # Preprocess dataset
    X = dataset[:,0]
   
    tokenizer = Tokenizer(filters='\t\n', char_level=True)
    tokenizer.fit_on_texts(X)
    #max_log_length = 880
    max_log_length = 1024

    #seq = tokenizer.texts_to_sequences([log_entry])
    #log_entry_processed = sequence.pad_sequences(seq, maxlen=max_log_length)

    model = load_model('securitai-lstm-model.h5')
    model.load_weights('securitai-lstm-weights.h5')
    model.compile(loss = 'binary_crossentropy', optimizer = 'adam', metrics = ['accuracy'])

    db = DB_Connector(DB_HOST, DB_USER, DB_PWD, DB_NAME)
    
    #g_read_log_thread = threading.Thread(target=read_log, args=(log_file,))
    #g_read_log_thread.start()
    g_read_log_thread.start()
    print "\nModel Compile Finish"
    print "DB Connect Success\n"

    while True:
    	
    	if g_query_queue:
    		query = g_query_queue.popleft()
    		query_seq = tokenizer.texts_to_sequences([query[0]])
    		query_processed = sequence.pad_sequences(query_seq, maxlen=max_log_length)
    		prediction = model.predict(query_processed)
    		#print prediction 
    		pred = 1 if prediction[0][0] >= 0.5 else 0
    		print query
    		db.insert([query[0], query[1],pred], DB_TABLE)
    		# insert label prediction[0][0] to database 
    	
    


if __name__ == '__main__':

    parser = optparse.OptionParser()
    parser.add_option('-f', '--file', action="store", dest="file", help="File csv for gen dict")
    parser.add_option('-i', '--input', action="store", dest="input", help="File log from which request's loaded ")
    options, args = parser.parse_args()

    if options.file is not None:
    	csv_file = options.file 
    else :
    	csv_file = "data.csv"
    
    print options.input, "- ", options.file 
    start = time.time()

    if options.input is None :
    	print "No input log file"
    	exit()
    g_read_log_thread = Read_Log_Thread(options.input)
    #predict_loop(csv_file)
    try: 
    	predict_loop(csv_file)
    	print 'haha'
    except:
   		traceback.print_exc(file=sys.stdout)
   		g_read_log_thread.stop()
		
