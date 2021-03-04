# STIXOps - Interface to STIX
### Table of contents
------------
- [Introduction](#Introduction)
- [Usage](#Usage)
- Elevate
- Validate
- Interface
- [Contributing](#Contributing)
- [Credits](#Credits)

------------

## Introduction
Threat Intelligence analysts often struggle with receiving or sharing information that is machine readable and contextual. Machines are not able to ingest plain data which we see on the web even if it has context and the data format readable by machines is often not shared. STIX is the solution for both.

Structured Threat Information Expression (STIX) is a language and serialization format used to exchange cyber threat intelligence (CTI). With STIX, all aspects of suspicion, compromise and attribution can be represented clearly with objects and descriptive relationships.

  

STIX information can be visually represented for an analyst or stored as JSON to be quickly machine readable. STIX's openness allows for integration into existing tools and products or utilized for your specific analyst or network needs.

  

This tool allows analysts to easily work with, convert and create STIX objects.

  
  

## Usage

To use this tool, first install the requirements using

  

pip3 install requirements.txt

  

After installing requirements launch the program by running

  

python3 main.py

  

### Elevate

To elevate a STIX 1.0/1.1 object into a STIX 2.0/2.1 we can use this option. To elevate a STIX 1 XML, move the XML file into the directory with the converter. After keeping the file in the same folder, select the 1'st option and enter the filename to elevate.

  

This would elevate the STIX 1 XML into a STIX 2 JSON

  

### Validate

We also have an option to validate/ verify the STIX 2 JSON object. To do this enter option 2 and enter the JSON filename to validate. This would result in an output mentioning if the JSON object is valid or not.

  

### Interface

This tool also has an option to create a STIX object. To do this enter 3, and choose for what you would like to create the object. After choosing your option, enter the required data to get a fully created, valid and machine readable STIX 2.1 JSON object.

## Contributing

  

We are constantly on the lookout for newer extensions to add to STIXOps. To contribute you can pull this repo, add your extensions and submit a merge request for adding your code directly in our repo!

  

## Credits

- https://oasis-open.github.io/cti-documentation/stix/intro.html

------------------------------------------------------------------------------------------------------------------------------

  
