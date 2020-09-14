import csv

STIGID = []
STIGSEVERITY = []
STIGDESCRIPTION = []
RULE_TITLE = []


Group_Title = "echo 'Group Title:  "
Discussion = "echo 'Discussion: "
SEVERITY = "echo 'Severity: "
file = " >> file.txt"
Finding = "echo 'Finding:'' "
rules = "echo 'Rule Title: "
d = "echo '|---------------------------------------------------------------------|' >> file.txt"

# specify csv file 
with open('', 'r') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
            DESC = row['description']
            ID = row['id']
            SEV = row['severity']
            IDsubstring = ID
            STIGID.append(IDsubstring)
            STIGSEVERITY.append(SEV)
            STIGDESCRIPTION.append(DESC)
            RULE_TITLE.append(row['title'])
            




for q in range(0,344):
	print("\n" + d + "\necho '" + STIGID[int(q)] + "'" + file + "\n" + Group_Title  + "' >> file.txt" + "\n" + SEVERITY + STIGSEVERITY[int(q)] + "'" + file + "\n" + rules + RULE_TITLE[int(q)] +  "'" + file + "\n"+ Discussion + " " + STIGDESCRIPTION[int(q)]  + "'" +  file + "\n" + d + "\n")
