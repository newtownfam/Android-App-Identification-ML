'''
CS AdvNetworks
Phase 2
Peter Christakos
Andrew Morrison

'''

import statistics
import csv

def read_csv_training(filename):
	allRows = []
	with open(filename) as csvfileS:
		readCSV = csv.reader(csvfile, delimiter = ',')
		for row in readCSV:
			rows = row[1:]
			allRows.append(rows)
	return allRows

def create_vector(allRows, app):
	vectors = []
	for row in allRows:
		if len(row) > 2:
			time = row[0]
			total_packets = row[1]
			ethtype = row[2]
			ttl = row[3]
			flags = row[4]
			total = get_total(row[5:])
			vector = [app, time, total_packets, ethtype, ttl, flags, total]
			vectors.append(vector)
	return vectors

def get_total(row):
	total = 0
	for i in row:
		total += int(i)
	return total

def write_vectors():
	trainingVector = []
	newsVector = create_vector(read_csv_training('/opt/news.csv'), "News")
	weatherVector = create_vector(read_csv_training('/opt/weather.csv'), "Weather")
	fruitninjaVector= create_vector(read_csv_training('/opt/fruitninja.csv'), "Fruit Ninja")
	#youtubeVector = create_vector(read_csv_training('/opt/youtube.csv'), "Youtube")
	wikipediaVector = create_vector(read_csv_training('/opt/wikipedia.csv'), "Wikipedia")

	trainingVector.extend(newsVector)
	trainingVector.extend(weatherVector)
	trainingVector.extend(fruitninjaVector)
	#trainingVector.extend(youtubeVector)  youtube not working
	trainingVector.extend(wikipediaVector)

	with open('/opt/training.csv', mode='w') as pcapfile:
		pcap_writer = csv.writer(pcapfile, delimiter = ',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		for vector in trainingVector:
			pcap_writer.writerow(vector)

write_vectors()