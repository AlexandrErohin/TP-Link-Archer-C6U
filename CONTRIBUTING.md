# Adding Support For Your Model

The best way would be great if you create PR with a new class for your router witch extends [AbstractRouter](https://github.com/AlexandrErohin/TP-Link-Archer-C6U/blob/main/tplinkrouterc6u/client.py#L16)

If you cannot do it, lets do next

## How It Works
1. We're going to open up the router's web management page and figure out what internal requests the webpage is making (what commands it's sending to the router) to do the tasks in question.  
2. We're then going to look at that data and parse it into the format that we need so the API functions can replicate those commands

## Steps
### Setup
1. Go over to the router's web management page (don't log in yet)
2. Open the Inspect window > Network tab (usually by pressing F12 and then clicking on "Network")
3. Tick the "Preserve Log" checkbox and set the filter to "XHR"
### Recording
4. Login to your router
5. Click on various buttons in the web management page "About", "Wifi clients", "Wired clients", "Turn on wifi", "Turn off wifi", "Turn on guest wifi", "Turn off guest wifi", etc
6. Once you've clicked on all the important options, finally click "Logout" and "Restart". (only do this if you have "Preserve Log" enabled)
### Export Captured Data
7. Right Click on the CGI files in the Inspect window's "Network" tab and export HAR
8. Compress the HARs into a ZIP/TAR
9. Create a new issue on this GitHub with the following template:
  - Title: [Model Name] Support Data
  - Description: (List of buttons clicked on in the router management page)
  - Attachment: Compressed file of your packet captures
  