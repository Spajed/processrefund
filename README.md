# Process Refund

An attempt to implment Process Doppelgänging
## Getting Started

Just clone the repo and open the .sln with Visual Studio 2015.

### Prerequisites

Currently this works only in x86, and it requires having MalExe.exe and Svchost.exe in the same folder.
If you are on x64 machine use svchost from syswow64.

### Problems with Process Doppelgänging
* You can not replace any file. If you try to replace  C:\windows\system32\svchost.exe you will get "Access Denied".
  Yet in the black hat slide show they show replacing "svchost.exe", but after viewing the DEMO image in the slide show
  it is clear they didn't replace svchost.exe in the demo but Vmmap.exe from sysinternals.
 ![alt text](https://raw.githubusercontent.com/spajed/processrefund/master/cheating.png) ![alt text](https://raw.githubusercontent.com/spajed/processrefund/master/cheating2.png)
## Acknowledgments

* https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf
