import json  # STIX to CSV converter
import csv
import os  # For TAXII connector
from stix2elevator import elevate  # STIX elevator
from stix2elevator.options import initialize_options
from stix2validator import validate_file, print_results  # STIX validator
from stix2slider import slide_file  # STIX slider
from stix2slider.options import initialize_options
from stix2 import *  # Python STIX interface
from stix2elevator import elevate
from stix2elevator.options import initialize_options


class STIXOps(object):

    def elevatefile(self, filename):
        """
        Convert a STIX 1 XML file to a STIX 2 JSON
        :param filename:
        """
        initialize_options ()
        with open (filename, 'r') as stixfile:
            results = elevate (stixfile.read ())
        print (results)

    def validatefile(self, filename):
        """
        Validate a STIX 2 file ensuring its authenticity
        :param filename:
        """
        results = validate_file (filename)
        print_results (results)

    def convert(self, filename):
        """
        Convert a STIX 2 JSON to a CSV file
        :param filename:
        """
        with open (filename) as json_file:
            data = json.load (json_file)
            stix_data = data['objects']
        data_file = open ('data_file.csv', 'w')
        csv_writer = csv.writer (data_file)
        count = 0
        for object in stix_data:
            if count == 0:
                header = object.keys ()
                csv_writer.writerow (header)
                count += 1
                csv_writer.writerow (object.values ())
                data_file.close ()

    def writeSTIX(self, option):
        """
        Create STIX 2.1 JSON files by answering few questions
        :param option:
        :return:
        """
        if option == 1:
            name = str (input ("Enter indicator name: "))
            pattern = str (input ("Enter pattern: "))
            indicator = indicator = Indicator (name=name,
                                               pattern=pattern,
                                               pattern_type="stix")
            return indicator

        elif option == 2:
            name = str (input ("Enter name: "))
            description = str (input ("Enter description: "))
            type = str (input ("Enter threat actor type: "))
            resource = str (input ("Enter resource level: "))
            role = str (input ("Enter role: "))
            motivation = str (input ("Enter primary motivation: "))
            alias = str (input ("Enter alias: "))
            threatactor = ThreatActor (name=name,
                                       description=description,
                                       threat_actor_types=type,
                                       resource_level=resource,
                                       roles=role,
                                       primary_motivation=motivation,
                                       aliases=alias)
            return threatactor

        elif option == 3:
            name = str (input ("Enter malware name: "))
            family = str (input ("Does the malware have any relations [True/ False]? "))
            description = str (input ("Enter malware description: "))
            malware_type = str (input ("Enter malware type: "))
            malware = Malware (name=name,
                               description=description,
                               is_family=family,
                               malware_types=malware_type)
            return malware

        elif option == 4:
            name = str (input ("Enter identity name: "))
            id_class = str (input ("Enter identity class: "))
            sector = str (input ("Enter sector: "))
            contact = str (input ("Enter contacts: "))
            identity = Identity (name=name,
                                 identity_class=id_class,
                                 sectors=sector,
                                 contact_information=contact)
            return identity

        elif option == 5:
            name = str (input ("Enter tool name: "))
            tool_type = str (input ("Enter tool type: "))
            description = str (input ("Enter description: "))
            phases = str (input ("Enter tool phases: "))
            tool = Tool (name=name,
                         tool_types=tool_type,
                         description=description)
            return tool

        elif option == 6:
            name = str (input ("Enter attack pattern name: "))
            description = str (input ("Enter attack pattern description: "))
            attackpattern = AttackPattern (name=name,
                                           description=description,
                                           )
            return attackpattern

        elif option == 7:
            name = str (input ("Enter report name: "))
            report_type = str (input ("Enter report type: "))
            description = str (input ("Enter report description: "))
            ref = str (input ("Enter object references: "))
            report = Report (name=name,
                             report_types=report_type,
                             description=description,
                             object_refs=ref)
            return report

        elif option == 8:
            name = str (input ("Enter campaign name: "))
            description = str (input ("Enter campaign description: "))
            objective = str (input ("Enter objective: "))
            campaign = Campaign (name=name,
                                 description=description,
                                 objective=objective)
            return campaign

        elif option == 9:
            name = str (input ('Enter vulnerability name: '))
            description = str (input ("Enter vulnerability description: "))
            labels = str (input ("Enter labels: "))
            vulnerability = Vulnerability (name=name,
                                           description=description,
                                           labels=labels)
            return vulnerability

    def init_options(self):
        option = int (input (
            "[+] Welcome to STIX ops. Enter task to perform\n [-][1] For "
            "elevating STIX 1 to STIX 2\n [-][2] For validating a STIX json file\n [-][3] For creating a STIX object "
            "via an interface\n --> "))
        if option == 1:
            filename = str (input ("[+] Enter filename to elevate [File must be in this directory]: "))
            self.elevatefile (filename)
        elif option == 2:
            filename = str (input ("[+] Enter filename to validate [File must be in this directory]: "))
            self.validatefile (filename)
        elif option == 3:
            option = int (input (
                "Enter option to parse\n [-][1] For indicator\n [-][2] For threat actor\n [-][3] For malware\n [-][4] "
                "For identity\n [-][5] For tool\n [-][6] For attack pattern\n [-][7] For report\n [-][8] For "
                "campaign\n [-][9] For vulnerability\n --> "))
            result = self.writeSTIX (option)
            print (result)

def main():
    stixops = STIXOps()
    stixops.init_options()

if __name__ == "__main__":
    main()
