# GoodRAM
An application for Windows NT that firstly detect the defect ram, and then reserve specified ranges of physical memory to prevent them from use, much like Linux's BadRAM.

## Details
Reserved the physical page that prevent being malloc to other application.
[AWE extension](http://msdn.microsoft.com/en-us/library/windows/desktop/aa366527(v=vs.85).aspx)

Please note that you'd first enable "Lock Page" privilege within your account.