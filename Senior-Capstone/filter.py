#! bin/python3
# filter.py
# This code serves as the main filter against reflected cross-site scripting.
import flask
from flask import escape 

def XSSFilter(requestParams):

    formattedFormData = []  
    
    whiteList = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10']
    blackList = ['<', '>', '&', "'", '"', '/', '\\', '.', "\\'", '.', '^', '$', '\'', '!', '=', '-', ':', '(', ')', '*', '`', '~' ]
    
    #formats parameters to remove extra characters added by flask when HTTP packet is sent to the server, appends formatted parameter to formattedFormData
    for x in requestParams:
        x = x.translate({ord(i): None for i in ('"[\']')})  
        formattedFormData.append(x) 
    print(formattedFormData)

    passfail = True     

    #checks user-entered parameter for "script" and also checks against the whitelist, fails check if characters are present that are not in the whitelist
    for param in formattedFormData:
        if "script" in param:       
            passfail = False        
        for char in param:
            if(char not in whiteList):      
                passfail = False            
            else:
                pass
    if (passfail == False):         
        return False
    #after passing whitelist, also checks parameter against blacklist for redundancy, fails check if there are characters present
    else:                           
        for param in formattedFormData:     
            for char in param:
                if(char in blackList):      
                    passfail = False        
                else:
                    pass
    #rejects HTTP packet if it did not pass all checks
    if(passfail == False):          
        return False                
    else:
        return True

    
