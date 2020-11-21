import json #STIX to CSV converter
import csv
import re
import os #For TAXII connector
from stix2elevator import elevate #STIX elevator
from stix2elevator.options import initialize_options
from stix2validator import validate_file, print_results #STIX validator
from stix2slider import slide_file #STIX slider
from stix2slider.options import initialize_options
from stix2 import * #Python STIX interface

def elevatefile(filename):
    command = 'stix2_elevator '+str(filename)
    os.system(command)

def validatefile(filename):
    results = validate_file(filename)
    print_results(results)

def convert(filename):
    with open(filename) as json_file:
        data = json.load(json_file)
        STIX_data = data['objects']
    data_file = open('data_file.csv', 'w')
    csv_writer = csv.writer(data_file)
    count = 0
    for writing in STIX_data:
        if count == 0:
            header = writing.keys()
            csv_writer.writerow(header)
            count += 1
            csv_writer.writerow(writing.values())
            data_file.close()

def reducefile(filename):
    initialize_options()
    results = slide_file(filename)
    print(results)
    file = open('slid.xml','w')
    file.write(results)

def connect(host, port, CONFIG_PATH):
    command = 'medallion --host '+str(host)+' --port '+str(port)+' '+str(CONFIG_PATH)
    os.system(command)

def writeSTIX(option):
    if option == 1:
        name = str(input("Enter indicator name: "))
        pattern = str(input("Enter pattern: "))
        indicator = indicator = Indicator(name=name,
                      pattern=pattern,
                      pattern_type="stix")
        return indicator

    elif option == 2:
        name = str(input("Enter name: "))
        description = str(input("Enter description: "))
        id = str(input("Enter ID: "))
        type = str(input("Enter threat actor type: "))
        resource = str(input("Enter resource level: "))
        role = str(input("Enter role: "))
        motivation = str(input("Enter primary motivation: "))
        alias = str(input("Enter alias: "))
        threatactor = ThreatActor(name=name,
                                  description=description,
                                  id=id,
                                  threat_actor_types= type,
                                  resource_level = resource,
                                  roles = role,
                                  primary_motivation = motivation,
                                  aliases = alias)
        return threatactor

    elif option == 3:
        name = str(input("Enter malware name: "))
        family = str(input("Does the malware have any relations [True/ False]? "))
        description = str(input("Enter malware description: "))
        type = str(input("Enter malware type: "))
        malware = Malware(name= name,
                          description = description,
                          is_family=family,
                          malware_types = type)
        return malware

    elif option == 4:
        name = str(input("Enter identity name: "))
        id = str(input("Enter identity ID: "))
        id_class = str(input("Enter identity class: "))
        sector = str(input("Enter sector: "))
        contact = str(input("Enter contacts: "))
        identity = Identity(name = name,
                            id = id,
                            identity_class = id_class,
                            sectors = sector,
                            contact_information = contact)
        return identity

    elif option == 5:
        name = str(input("Enter tool name: "))
        type = str(input("Enter tool type: "))
        id = str(input("Enter tool id: "))
        description = str(input("Enter description: "))
        phases = str(input("Enter tool phases: "))
        tool = Tool(name = name,
                    tool_types = type,
                    id = id,
                    description = description)
        return tool

    elif option == 6:
        name = str(input("Enter attack pattern name: "))
        id = str(input("Enter attack pattern ID: "))
        description = str(input("Enter attack pattern description: "))
        attackpattern = AttackPattern(name = name,
                                      id = id,
                                      description = description,
                                      )
        return attackpattern

    elif option == 7:
        name = str(input("Enter report name: "))
        type = str(input("Enter report type: "))
        id = str(input("Enter report ID: "))
        description = str(input("Enter report description: "))
        ref = str(input("Enter object references: "))
        report = Report(name = name,
                        report_types = type,
                        id = id,
                        description = description,
                        object_refs = ref)
        return report

    elif option == 8:
        name = str(input("Enter campaign name: "))
        description = str(input("Enter campaign description: "))
        objective = str(input("Enter objective: "))
        campaign = Campaign(name = name,
                            description = description,
                            objective = objective)
        return campaign

    elif option == 9:
        name = str(input('Enter vulnerability name: '))
        id = str(input("Enter vulnerability ID: "))
        description = str(input("Enter vulnerability description: "))
        lables = str(input("Enter labels: "))
        vulnerability = Vulnerability(name = name,
                                      id = id,
                                      description = description,
                                      labels = labels)
        return vulnerability

def start():
    option = int(input("[+] Welcome to STIX scripts. Enter task to perform\n [-][1] For converting STIX json to CSV\n [-][2] For elevating STIX 1 to STIX 2\n [-][3] For validating a STIX json file\n [-][4] For reducing a STIX 2 json object to a STIX 1 XML\n [-][5] For creating a STIX object via an interface\n --> "))
    if option == 1:
        filename = str(input("[+] Enter filename to convert [File must be in this directory]: "))
        convert(filename)
    elif option == 2:
        filename = str(input("[+] Enter filename to elevate [File must be in this directory]: "))
        elevatefile(filename)
    elif option == 3:
        filename = str(input("[+] Enter filename to validate [File must be in this directory]: "))
        validatefile(filename)
    elif option == 4:
        filename = str(input("[+] Enter filename to reduce [File must be in this directory]: "))
        reducefile(filename)
    elif option == 5:
        option = int(input("Enter option to parse\n [-][1] For indicator\n [-][2] For threat actor\n [-][3] For malware\n [-][4] For identity\n [-][5] For tool\n [-][6] For attack pattern\n [-][7] For report\n [-][8] For campaign\n [-][9] For vulnerability\n --> "))
        result = writeSTIX(option)
        print(result)

#convert("data.json")
#elevatefile("data.xml")
#validatefile("data.json")
#reducefile('data.json')
#result = writeSTIX(5)
#print(result)
start()
