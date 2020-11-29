#! bin/python3
# This code is the server-side code for the application, containing the server information, server-side data storage, application redirection, and filtering for stored cross-site scripting.

from filter import XSSFilter   #import filter file 
import os   
from flask import request, redirect, Flask, render_template, url_for  
app = Flask(__name__)      #create flask application


#Each app.route determines what will happen each time the browser is redirected to the page specified in the app.route parameter

#displays the home page
@app.route('/')
def index():
    return render_template('index.html')           

#displays the page vulnerable to reflected XSS
@app.route('/VReflected.html', methods=['GET', 'POST'])
def VReflected():
    return render_template('VReflected.html')      

#displays the page secure from reflected XSS
@app.route('/SReflected.html', methods=['GET', 'POST'])
def SReflected():
    return render_template('SReflected.html')      

#displays an image of a koala when called. This is the "normal" function of the webpage.
@app.route('/koalapage', methods=['GET', 'POST'])   
def Koala():
    return render_template('koalapage.html')       

#called when user enters search into secure search bar, calls FilterData() from filter to check for XSS, if no XSS present, app will load an image of a koala if user searched for one
@app.route('/reflectedsecure', methods=['GET', 'POST'])         
def FilterData():                                   
    requestParams = []                             
    requestParams.append(str((request.args.getlist('animalSearched'))))    
    if(XSSFilter(requestParams) == True):                       
        if (request.args['animalSearched'].lower() == 'koala'): 
            return redirect('/koalapage')                          
        else:       
              return ("We did not have a picture of a " + request.args['animalSearched'] + " in our database.")     
    else:
        return redirect('/SusActivity.html')            

#called when user uses the insecure search bar. Does not use a filter and returns user input directly. This code is vulnerable
@app.route('/reflectedvuln', methods=['GET', 'POST'])      
def vulnImageLoad():
    if (request.args['animalSearched'].lower() == 'koala'):
        return redirect('/koalapage')
    else:
        return ("We did not have a picture of a " + request.args['animalSearched'] + " in our database.")

#displays suspcious activity page when called
@app.route('/SusActivity.html', methods=['GET', 'POST'])  
def SusActivity():
    return render_template('SusActivity.html')

#returns insecure comment submission page
@app.route('/commentSubmit.html', methods=['GET', 'POST'])   
def CommentPage():
    return render_template('commentSubmit.html')


#Several server side lists used to store comments for pages secure from and vulnerable to Stored XSS
comments = []
comments2 = []
formattedComments = []          
formattedComments2 = []
sanitizedComments = []

#server accept HTTP packet from comment submission, parses parameter to remove excess quotes added by flask, stores parameter into list without further filtering
@app.route('/commentrecieved', methods=['GET', 'POST'])
def storeComment():
    comments.append(str((request.args.getlist('comment'))))       
    for x in comments:
        x = x.translate({ord(i): None for i in ('"[\']')})     
        formattedComments.append(x)                             
    return redirect('/')

#Server returns the exact unfiltered comments list from /commentrecieved. This code is vulnerable
@app.route('/VStored.html', methods=['GET', 'POST'])
def VStored():
    return(str(formattedComments))                      

#Displays the secure comment submission page
@app.route('/secureCommentSubmit.html', methods=['GET', 'POST'])
def secureCommentSubmit():
    return render_template('secureCommentSubmit.html')     


#Instead of calling another file for the XSS filter like the reflected XSS page does, the stored XSS filter resides here in the app.route below

#Filter to check for stored XSS, utilizes a Python dictionary containing illegal character/escaped character key/value pairs
@app.route('/securecommentrecieved', methods=['GET', 'POST'])
def storeCommentSecurely():
    blackListDict = {'<':'&#60', '>': '&#62', "'": '&#39', '"': '&#34', '(': '&#40', ')': '&#41', '{': '&#123', '}': '&#125', ';': '&#59', '-': '&#45', '.': '&#46', ',': '&#44', '*': '&#42', '$': '&#36', '!': '&#33', '/': '&#47', '?': '&#63', '=': '&#61', ':': '&#58', '_': '&#95', '`': '&#96', '~': '&#126'}   
    comments2.append(str((request.args.getlist('comment'))))    
    for x in comments2:
        x = x.translate({ord(i): None for i in ('"[\']')})  
        for y in blackListDict: 
            for char in x:          
                if char == y:
                    x = x.replace(char, blackListDict[y])       
    sanitizedComments.append(x)        
    print(str(sanitizedComments))       
    return redirect('/')

#Displays the properly escaped, safe comments list
@app.route('/SStored.html', methods=['GET', 'POST'])           
def SStored():
    securecommentstring = str(sanitizedComments)
    print(securecommentstring)
    return(securecommentstring)

#Initialized the flask app defining the IP address and port it will run on
if __name__ == "__main__":                          
    port = int(os.environ.get('PORT', 5000))
    app.run(host='192.168.225.131', port = port)