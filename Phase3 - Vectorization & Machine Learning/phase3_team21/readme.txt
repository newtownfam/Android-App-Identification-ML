Andrew Morrison
Peter Christakos
Phase 3
Advanced Networks

Python Package Dependencies:
(using python3)
sklearn
numpy
pyshark

To run our code: 

>> classifyFlows <arguments> 

where arguments are the filenames of your pcap files. 
Our code uses the provided csv file to train its models, and all other classes to populate the csvs and vectorize them for training.

** IMPORTANT**
On line 140 of classifyFlows, we open our training csv file which was stored in '/opt/training.csv', your path will need to be changed depending on where you store the files.

Limitations:

My team got stuck on classifying issues for a long time, and as a result we ended up falling short in some areas. Our model definitely is not perfect, but can predict the correct app about 50% of the time. 

We designed our project from the start to predict each flow individually, which prevented us from being able to score our predictions and compare them. For this reason, we printed out both our predictions from our svm and linear regression model. 

Our youtube pcap files somehow became unusable and would only produce errors. We did not have time to make more, so our model cannot predict youtube flows.

Finally, we recieve two strange DataConversionWarnings that we were unable to avoid.


