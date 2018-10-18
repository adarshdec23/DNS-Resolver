!!! 
!!!
!!! If the Python files are being copied to be run outside the folder, then the config/config.py file must also be copied. This file contains timeout, root ip etc
!!!
!!!

Folder Structure: 

mydig.py: Solution for Question 1. 
            Run it as: python3 mydig.py <url> <record_type>
            Eg: python3 mydig.py google.com NS
            

q2.py: Solution for DNSSEC
            Run it as: python3 q2.py <url> <record_type>
            Eg: python3 q2.py example.com
            
q3.py: Solution for Question3
            Run it as python3 q3.py
       This does not need any parameters to run. It outputs a Matplotlib graph containing the CDF after making queries to the top 25 websites as required.
            
            
Prerequisites: 
        The following modules must be installed: dnspython (for making DNS queries), numpy and matplotlib (for plotting the CDF)
        Commands to run:
            pip install dnspython
            pip install numpy
            pip install matplotlib
            
            
Documents: 
        The following documents are available at the root:
        - mydig_output.txt : Contains the output of for Question 1.
        - DNSSEC.pdf: Contains the DNSSEC implementation details.
        - q3.pdf: Contains the graph from Question 3 and it's implications. 