# cisco_parser_API_swagger
Python script to collect data from cisco devices and then after filtering it pushing filtered data into netbox via API
"""""""""""""""""""""""""""""""
          Tutorial
"""""""""""""""""""""""""""""""




To run script you should to print commands below:

python3 main.py -ip 10.10.0.0 -s ios -p -did 220

Where:
    '-ip  'it is ip address of router/switch'
    
    '-s   'it is platform of device, necessary for syntaxis of CiscoConfParse: nxos,ios etc...'
    
    '-p   'add -p to push data to Netbox'
    
    '-did 'device id in Netbox'



    
