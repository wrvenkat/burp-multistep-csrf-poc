Ever wanted to combine the individual CSRF POCs in Burp into a single HTML? Or ever wished that Burp generated CSRF POCs combining two or more requests? Look no further!  

Multi-step CSRF POC extension for Burp combines two or more requests into a single HTML POC. This extension also gives you an option to generate the multi-step POC using form-based, XHR or jQuery based HTML.  

The extension makes use of the Python modules [request_parser](https://github.com/wrvenkat/request_parser) and [request_generator](https://github.com/wrvenkat/request_generator) to parse requests and generate code.

## Demo
The following demo shows the usage and feature of this Multi-step CSRF POC extension.
<br>
<br> 
![alt text](https://github.com/wrvenkat/burp-multistep-csrf-poc/blob/master/.md/gifs/multi-step-csrf-demo.gif)

## Getting Started
### Installing the extension
* Download Jython standalone JAR into a directory.
* Select this directory in Burp suite's "Java Environment" which can be reached from "Extender" -> "Options".
* Download the latest release from releases and load it into Burp by going to "Extender" -> "Extensions" -> click "Add" and select the downloaded extension JAR file.

### Using the extension

#### Generating a new multi-step CSRF POC
* Once loaded, select a few requests in Burp's "HTTP history" tab.
* Right-click and select "Multi-Step CSRF POC" -> "Generate new Multi-Step CSRF POC".

#### Adding to existing CSRF POC
* Make sure an existing Multi-step CSRF POC window is open.
* Select one or more requests in Burp's "HTTP history" tab.
* Right-click and select "Multi-Step CSRF POC" -> "Add to existing POC" and select the POC window to which the new request(s) need to be added to.

#### Other Features
The extension supports,
* reordering the requests in CSRF POC window.
* modifying the requests in the Multi-step CSRF POC window and regenerating HTML.
* removing added requests.
* copying the generated HTML code to clipboard.
* exceptions are displayed in the bottom most text area while stack trace for the exceptions are displayed in the "Errors" tab for the extension.