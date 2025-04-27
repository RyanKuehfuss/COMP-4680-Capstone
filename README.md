# COMP-4680-Capstone

Requirements:

Download all python libraries within requirements.txt by doing "pip install -r requirements.txt"
Linux enviornment (All testing done on Ubuntu WSL)


Steps to use:

Fill in the ipSender and ipReceiver fields in RunTest.py. The receiver should be the pc you run on, and the sender can be any other IP (** cannot be the same IP). we used an ip on the same local network in our testing. 
"Python3 Run.py"
then on another terminal on the same system, do "Python3 RunTest.py"
Select one of the 6 options to launch a test.
Test cases 1,3,4,5 will pass as normal and nothing will appear.
Test cases 2,6 will be flagged as anomalous, and create a log. 
