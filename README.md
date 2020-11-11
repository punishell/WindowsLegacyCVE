# WindowsLegacyCVE

### CVE-2017-10204


VirtualBox: Windows Process DLL Signature Bypass EoP
Platform: VirtualBox v5.1.22 <a href="https://crrev.com/115126" title="" class="" rel="nofollow">r115126</a> x64 (Tested on Windows 10)
Class: Elevation of Privilege

Summary:
The process hardening implemented by the VirtualBox driver can be circumvented to load arbitrary code inside a VirtualBox process giving access to the VBoxDrv driver which can allow routes to EoP from a normal user.

Description:
 
NOTE: I don’t know if you consider this an issue or not, however you fixed the last bypass I sent so it’s possible you still consider it a security boundary.
 
The ring 3 process hardening in VirtualBox adds three hooks to module loading to try and prevent untrusted code being loaded into the process, LdrLoadDll, NtCreateSection and a LDR DLL notification. Each will try and verify a DLL load and either reject the load with an error or kill the process is it’s not possible to prevent it from occurring. Looking at the hooks there a couple of issues which when combined together allow a user to inject an arbitrary DLL into a protected process.
 
The location checks are not very rigorous. As far as I can tell arbitrary files need to be owned by an admin/trustedinstaller but this check is waived if the file is in system32/WinSxS. However this doesn’t take into account that there are some directories which can be written to inside system32 such as Tasks.
The code to enforce specific certificates doesn’t seem to be enabled so at the very least combined with 1, you can load any validly signed file.
 
It might be considered that 2 isn’t an issue as getting a signing cert could be a sufficient burden for a “malicious” attacker, so instead it’s worth considering what else the weak path checking allows you to do. The handling of DLL paths has some interesting behaviours, most interestingly there’s the behaviour where if no file extension is added to the path then the loader will automatically append .DLL to it. This is actually implemented inside LdrLoadDll, this leads to our third problem:
 
3.  If the path passed to LdrLoadDll doesn’t have an extension then the protection code will signature check the extension less file but the loader will load the file with a .DLL extension. E.g. if trying to load \path\abc then \path\abc is signature checked but \path\abc.dll is loaded. 
 
When combined with the ability to bypass the owner check we can drop an arbitrary valid signed file alongside our untrusted DLL and exploit this TOCTOU to load an arbitrary unsigned DLL. The following will show inside the VboxHardening.log when loading the file testdll.
 
2064.492c: \Device\HarddiskVolume4\Windows\System32\Tasks\dummy\testdll: Owner is not trusted installer
2064.492c: \Device\HarddiskVolume4\Windows\System32\Tasks\dummy\testdll: Relaxing the TrustedInstaller requirement for this DLL (it's in system32).
2064.492c: supHardenedWinVerifyImageByHandle: -> 0 (\Device\HarddiskVolume4\Windows\System32\Tasks\dummy\testdll) WinVerifyTrust
2064.492c: supR3HardenedWinVerifyCacheInsert: \Device\HarddiskVolume4\Windows\System32\Tasks\dummy\testdll
2064.492c: supR3HardenedMonitor_LdrLoadDll: pName=c:\windows\system32\tasks\dummy\testdll (rcNtResolve=0xc0150008) *pfFlags=0x0 pwszSearchPath=0000000000002009:<flags> [calling]
 
This shows that it successfully passed the signature check inside the LdrLoadDll hook, however one of the other hooks should try and recheck the real testdll.dll file when it gets loaded instead. As the name of this file won’t match the cached signature check it should still fail to complete loading. This is where the fourth issue comes in:
 
4. When doing the check inside supHardenedWinVerifyImageByHandle with WinVerifyTrust disabled (i.e. when in the DLL load notification hook) and the target file has no signature information an incorrect error code is returned which looks like success leading to the DLL being allowed to load and execute. 
 
Specifically when supR3HardenedDllNotificationCallback is called it passes true to the fAvoidWinVerifyTrust parameter of supR3HardenedScreenImage. This first uses the RT code to check if the file is signed or not, if we use an unsigned file then this will return the error VERR_LDRVI_NOT_SIGNED (-22900). Later in supHardenedWinVerifyImageByLdrMod this error is checked and the function supHardNtViCheckIfNotSignedOk is called. This seems to result in the error coding changing from an error to VINF_LDRVI_NOT_SIGNED (22900) which is actually a success code. Normally this would be overridden again by the call to WinVerifyTrust but because that’s disabled the final result of this process is the DLL notification callback thinks the signature check was successful even though it wasn’t. This results in the DLL being allowed to complete loading.
 
For example the following is a snippet of the output when the bypass occurs.
 
2064.492c: \Device\HarddiskVolume4\Windows\System32\Tasks\dummy\TestDll.dll: Owner is not trusted installer 
2064.492c: \Device\HarddiskVolume4\Windows\System32\Tasks\dummy\TestDll.dll: Relaxing the TrustedInstaller requirement for this DLL (it's in system32).
2064.492c: supR3HardenedWinVerifyCacheScheduleImports: Import todo: #1 'user32.dll'.
2064.492c: supR3HardenedWinVerifyCacheScheduleImports: Import todo: #2 'advapi32.dll'.
2064.492c: supHardenedWinVerifyImageByHandle: -> 22900 (\Device\HarddiskVolume4\Windows\System32\Tasks\dummy\TestDll.dll)
2064.492c: supR3HardenedWinVerifyCacheInsert: \Device\HarddiskVolume4\Windows\System32\Tasks\dummy\TestDll.dll
2064.492c: supR3HardenedDllNotificationCallback: load   00007ff8a8600000 LB 0x00027000 c:\windows\system32\tasks\dummy\testdll.DLL [fFlags=0x0]
2064.492c: supR3HardenedScreenImage/LdrLoadDll: cache hit (Unknown Status 22900 (0x5974)) on \Device\HarddiskVolume4\Windows\System32\Tasks\dummy\TestDll.dll [avoiding WinVerifyTrust]
2064.492c: Detected loader lock ownership: rc=Unknown Status 22900 (0x5974) '\Device\HarddiskVolume4\Windows\System32\Tasks\dummy\TestDll.dll'.
2064.492c: supR3HardenedWinVerifyCacheProcessWvtTodos: 22900 (was 22900) fWinVerifyTrust=0 for '\Device\HarddiskVolume4\Windows\System32\Tasks\dummy\TestDll.dll' [rescheduled]
 
This combination of issues results in being able to inject arbitrary executable code into a VirtualBox protected process and access the resources such as the kernel driver that this would provide.

Proof of Concept:

I’ve provided a PoC DLL which will be loaded through abusing the VBox COM Client loading process in source form. I’ve also provided a registry file which will need to be imported.
 
Prerequisites: 
The DLL must be compiled in release mode for the architecture you’re going to run VirtualBox on. Then follow these steps:
 
1) Create the directory c:\windows\system32\tasks\dummy on the command line using ‘mkdir c:\windows\system32\tasks\dummy’
2) Import the provided .reg file to setup the COM hijack using the command line ‘reg import keys.reg’
3) Copy a valid signed file (such as VirtualBox.exe) to the file c:\windows\system32\tasks\dummy\testdll.
4) Copy the compiled PoC dll to c:\windows\system32\tasks\dummy\testdll.dll.
5) Start a VM. Each process the DLL is injected into will show a message box. This will include the protected VirtualBox.exe process.

Expected Result:
Untrusted DLL loading should fail inside a protected process.

Observed Result:
DLL is loaded into the protected process.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.




Found by: forshaw


### CVE-2017-10129


VirtualBox: Windows Process DLL UNC Path Signature Bypass EoP
Platform: VirtualBox v5.1.22 <a href="https://crrev.com/115126" title="" class="" rel="nofollow">r115126</a> x64 (Tested on Windows 10)
Class: Elevation of Privilege

Summary:
The process hardening implemented by the VirtualBox driver can be circumvented to load arbitrary code inside a VirtualBox process giving access to the VBoxDrv driver which can allow routes to EoP from a normal user.

Description:
 
NOTE: I don’t know if you consider this an issue or not, however you fixed the last bypass I sent so it’s possible you still consider it a security boundary.

This is a similar issue in impact to the one I reported in S0867394 but it uses a completely different mechanism. Once again we can use a current user COM registration to redirect the VBOX COM object to an arbitrary DLL path. However in this case rather than using MS signed code or abusing path behaviours in DLL library loading (and a bug in the hardening code) we'll instead abuse the way Windows handles image mapping from a kernel perspective.

On Windows mapped DLLs use an Image Section under the hood. This is a special type of file mapping where the parsing and relocating of the PE file is all handled by the kernel. To allow for sharing of image mappings (so ideally the kernel only needs to do the parsing and relocation once) the kernel memory manager ties the file object to an existing section object by using a unique section pointer set by the file system driver. The interesting thing about this is the section pointer doesn't necessarily ensure the file hasn't changed, just that the file system considered the file the "same". Therefore it's possible that opening a file and reading it returns a completely different PE file than the one you'll get if you then map that file as an image section.

If we can get a file mapped via one section pointer, then change the file underneath to be a different one we can exploit this. However on a default NTFS drive this isn't really possible due to things like sharing (outside of having admin privileges) so we need to use something different. For that we can use the SMB client file system. When you open a file via a UNC path any queries for the path return a MUP device path such as \Device\Mup\server\share\path\file.dll. When this is first mapped into memory the section pointer is used to refer to any file with that same path, however when opening the file the SMB client still needs to go to the server and receive the current data. Even with SMB supporting locking hopefully you can see that if you control the server as an admin then all bets are off with regards to returning the same data. In the worst case you could compile SAMBA with some custom code to do the attack (not that it would be needed). SMB also supports all the necessary file operations the hardening code checks for such as requesting the file Owner so we can pass all the checks with this. So to do the attack we can do the following:

1. Load our untrusted DLL from \\server\share\path\file.dll and map it into memory using something like LoadLibrary. This mapping needs to stay valid for the entire exploit to work.
2. Change the untrusted DLL file on the server to one which is a valid file for the hardening code and also has a owner set appropriately.
3. Add current user COM redirection to point VBOX class to the original UNC path.
4. Run VirtualBox. The hardening code will read the UNC path and find it's a valid file, however when the kernel maps the image section in NtMapViewOfSection it will find it's already got a mapped image loaded and will use that instead, the mapped image is of course the untrusted DLL, not the one the hardening code checked.
5. The untrusted DLL will be loaded into memory and executed.

This is easy enough using a remote server but it would be more useful to exploit locally. For that we can use the default admin shares on a Windows system which expose the drives over SMB. Even though their primary purpose is for administration you don't need to be an administrator if you access them locally, you'll just get access just a the same user account. So we can do the redirection of the file access as follows:

1. Set up a path such as c:\poc somewhere on an NTFS drive and copy the untrusted DLL to that directory called vboxc.dll.
2. Create a mount point (a directory symlink) at c:\poc\dummy which redirects to c:\poc.
3. Map \\localhost\c$\poc\dummy\vboxc.dll. The SMB server will follow the mount point and open c:\poc\vboxc.dll, however from the client perspective (even though we're on the same machine) the file still thinks the original UNC path.
4. Change the mount point to c:\program files\oracle\virtualbox.  Now when accessing the UNC path the file opened will be the real vboxc.dll file which is signed and has a trusted owner.

The main reason this works is the fact that from a client perspective the filename never changes therefore the hardening code can't do much about it. The only way to tell the mapped file doesn't match the original would be to check the acual mapped image data as requesting its path using the memory manager would just return the UNC path. Ultimately I guess you probably shouldn't be trusting code on UNC paths.
 
Proof of Concept:

I’ve provided a PoC which will abuse the VBox COM Client loading process in source form.
 
Prerequisites: 
Compile the supplied project in release mode using VS2015. I've only provided x64 version, it should work on x86 but I've not got anything to test it on. Then follow these steps:
 
1) Create the directory c:\poc and copy RunPoc.exe, NtApiDotNet.dll and the fake vboxc.dll to that directory.
2) Execute RunPoc.exe, it should print that it's successfully loaded the file. At this point DO NOT close the RunPoc executable as the file needs to stay mapped.
3) Start a VM. Each process the DLL is injected into will show a message box. This will include the protected VirtualBox.exe process.
4) When done testing hit enter in the RunPoc executable to ensure the keys get deleted.

Expected Result:
Untrusted DLL loading should fail inside a protected process.

Observed Result:
DLL is loaded into the protected process.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.



Found by: forshaw

### Windows: PPL Process Injection EoP 




Windows: PPL Process Injection EoP
Platform: Windows 10 1703 x64
Class: Elevation of Privilege

Summary:
It’s possible to inject code into a PPL protected process by hijacking COM objects leading to accessing PPL processes such as Lsa and AntiMalware from an administrator.

Description:

NOTE: I don’t know if you consider this an issue or not. I’ve spoke to a few people in MSRC who seem to think Admin -> PPL is not a serviceable issue. As I was going to blog about the old VirtualBox issue I thought it was prudent to send it to you just in case. I’m not really sure what you’d fix other than maybe banning certain DLLs from PPLs. I didn’t want someone to report the issue to you after the blog post without you at least being aware.

This is basically a rework of an issue I found in VirtualBox (<a href="https://bugs.chromium.org/p/project-zero/issues/detail?id=1103" title="" class="" rel="nofollow">https://bugs.chromium.org/p/project-zero/issues/detail?id=1103</a>). Basically you can hijack a COM registration for an object that you know a PPL service will use. You can then chain through a Scriptlet (which uses scrobj.dll which is allowed to be loaded into a PPL), which runs arbitrary JScript/VBScript and finally we use that to bootstrap arbitrary .NET from a byte array using my DotNetToJScript tool (which is the entire reason I wrote it).

Of course to do this we need to be Admin, but considering Admin isn’t allowed to even stop PPL services directly it would seem to be a somewhat valid security boundary, at least if SecureBoot is being enforced and protecting things like debug configuration. For example you could implement it in a way to get code running in a PPL on Win10S and create arbitrary cache signed executable code using NtSetCachedSigningLevel. 

But if you don’t want to fix it, that’s fine with me. After all if people want a secure LSASS they should use IUM/VSM anyway.

Proof of Concept:

I’ve provided a PoC as a C# project. When executed a scriptlet is registered which implements a COM server (CLSID: {AC18D171-6374-4672-AB71-7E9E76970A16}) so when our PPL service tries to load the TaskScheduler COM object it gets redirected via a TreatAs to the fake COM server. This loads a JScript implementation which bypasses the signature checking (as scrrun.dll/jscript.dll etc are MS signed system binaries). It then gets full execution by bootstrapping some arbitrary .NET code from memory (so there’s no DLL to verify), which then just drops a protection.txt file to the system temp folder with the protection levels of the process it found itself in.

Note that this POC only gets use PPL/Windows level, not WindowsTcb. You might be able to get Tcb but I didn’t think it was worth the effort. This level at least allows you to compromise PPL LSASS and AntiMalware (as well as any other Windows level PPLs).

1) Compile the project in release mode.
2) Copy CreatePPL.exe and all associated libraries to a location on the test machine.
3) Run the CreatePPL executable as an administrator. This will create a PPL service using clipup.exe as the host (which is signed up to Windows PPL level), adds the TreatAs key to redirect the TaskScheduler, registers a scriptlet and starts the service.

Expected Result:
Loading Scriptlet code into memory should fail

Observed Result:
Scriptlet code is loaded. The file %windir%\temp\protection.txt should be written with the service protection level which should be PPL/Windows.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse
or a patch has been made broadly available, the bug report will become
visible to the public.




Found by: forshaw


### CVE-2017-11823


Windows: WLDP/MSHTML CLSID UMCI Bypass 
Platform: Windows 10 S (thought should be anything with UMCI)
Class: Security Feature Bypass

Summary:
The enlightened lockdown policy check for COM Class instantiation can be bypassed in MSHTML hosts leading to arbitrary code execution on a system with UMCI enabled (e.g. Device Guard)

Description:

Scripting hosts are supposed to check against the Windows Lockdown Policy (WLDP) before instantiating arbitrary COM classes. This is typically done by calling WldpIsClassInApprovedList from WLDP.DLL before instantiating any COM class. For example in the case of JScript’s ActiveXObject the ProgID is passed to CLSIDFromProgID by the script host and the resulting CLSID is passed to WLDP to determine what’s allowed.

It’s possible to circumvent this check by using the COM TreatAs key to redirect one of the limited (8) allowed CLSIDs to an arbitrary class and get it instantiated. However you can’t do this using ActiveXObject as CLSIDFromProgID will return the resulting CLSID from looking up TreatAs. That said there is a race condition here. However in an MSHTML Local Machine Zone scenario you can bypass it by using an OBJECT tag. In this case MSHTML parses the classid attribute and checks that CLSID against WLDP. It then proceeds to create it using CoCreateInstance which follows TreatAs and creates a different object.

This does require modification of the registry to work, but I think that’s in scope. The reason I’m reporting this one is I think it’s a bug in MSHTML, rather than in an application you can easily block (at least if you want to disable

Proof of Concept:

I’ve provided a PoC is two files, a text file to set-up the registry and a HTML file. The registry file is in the REGINI format which allows it to work on Win10S as while reg.exe and regedit.exe are blocked regini.exe isn’t. The HTML file can be run inside IE or my prefered option HTML Help. You could even make the PoC file a CHM but I didn’t. The PoC can bootstrap things like untrusted .NET but for simplicity it doesn’t.

1) Unpack the PoC and ensure the HTML file does NOT have MOTW.
2) From the explorer Run dialog execute “regini path\to\keys.txt”
3) Execute the HTML file from the Run dialog using “hh path\to\shell.html”

Expected Result:
The class creation should fail.

Observed Result:
The class creation succeeded and the HTML file executed notepad.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse
or a patch has been made broadly available, the bug report will become
visible to the public.




Found by: forshaw



### Windows: WLDP/MSHTML CLSID UMCI Bypass 
Platform: Windows 10 with UMCI
Class: Security Feature Bypass

Summary:
The enlightened lockdown policy check for COM Class instantiation can be bypassed in Scriptlet hosts leading to arbitrary code execution on a system with UMCI enabled (e.g. Device Guard)

Description:

This is effectively a variant on the bug reported as case 39754. In that case the issue was with MSHTML's handling of object elements in an HTML page. As the object was specified using a CLSID it the WLDP check was only for that top level class but it was possible to redirect it to an arbitrary COM class using a TreatAs key in the COM registration.

This variant instead uses scriptlets, which can be executed on their own, or as WSF files inside WSH. These file formats also support an object element which has the same behavior.

Proof of Concept:

I’ve provided a PoC as two files, a text file to set-up the registry and a WSF file. The registry file is in the REGINI format. The WSF should be run in wscript/cscript which means you can't test this on Win10S by default.

1) Unpack the PoC and ensure the files do NOT have MOTW.
2) From the explorer Run dialog execute “regini path\to\keys.txt”
3) Rename the poc.txt file to poc.wsf.
3) Execute the WSF file from the Run dialog using “wscript path\to\poc.wsf”

Expected Result:
The class creation should fail.

Observed Result:
The class creation succeeded and the WSF file executed notepad.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse
or a patch has been made broadly available, the bug report will become
visible to the public.



Found by: forshaw

### CVE-2017-11830


Windows: CiSetFileCache TOCTOU Security Feature Bypass
Platform: Windows 10 10586/14393/10S not tested 8.1 Update 2 or Windows 7
Class: Security Feature Bypass

Summary:
It’s possible to add a cached signing level to an unsigned file by exploiting a TOCTOU in CI leading to to circumventing Device Guard policies and possibly PPL signing levels.

Description:

Windows Code Integrity has the concept of caching signing level decisions made on individual files. This is done by storing an extended attribute with the name $KERNEL.PURGE.ESBCACHE and filling it with related binary information. As the EA name is a kernel EA it means it can’t be set by user mode code, only kernel mode code calling FsRtlSetKernelEaFile. Also crucially it’s a purgeable EA which means it will be deleted automatically by the USN journal code if any attempt is made to write to the file after being set. 

As far as I can tell the binary data doesn’t need to correspond to anything inside the file itself, so if we replace the contents of the file with a valid cached signing level the kernel is entirely relying on the automatic purging of the kernel EA to prevent spoofing. To test that theory I copied the EA entry from a valid signed file onto an unsigned file with a non-kernel EA name then used a disk editor to modify the name offline. This worked when I rebooted the machine, so I was confident it could work if you could write the kernel EA entry. Of course if this was the only way to exploit it I wouldn’t be sending this report.

As user mode code can’t directly set the kernel EA the facility to write the cache entry is exposed through ZwSetCachedSigningLevel(2). This takes a number of arguments, including flags, a list of associated file handles and the target handle to write the EA to. There seems to be 3 modes which are specified through the flags:

Mode 1 - This is used by mscorsvw.exe and seems to be used for blessing NGEN binaries. Calling this requires the caller to be a PPL so I didn’t investigate this too much. I’m sure there’s probably race conditions in NGEN which could be exploited, or ways to run in a PPL if you’re admin. The advantage here is you don’t need to apply the cache to a signed file. This is what piqued my interesting in the first place.
Mode 2 - Didn’t dig into this one TBH
Mode 5 - This sets a cache on a signed file, the list of files must only have 1 entry and the handle must match the target file handle. This is the one we’ll be exploiting as it doesn’t require any privileges to call.

Looking through the code inside the kernel the handles passed to ZwSetCachedSigningLevel are also passed as handles into CiSetFileCache which is slightly odd on the face of it. My first thought was you could race the handle lookup when ObReferenceObjectByHandle is called for the target handle and when the code is enumerating the list of handles. The time window would be short but it’s usually pretty easy to force the kernel to reuse a handle number. However it turns out in Mode 5 as the handle is verified to be equal the code just uses the looked up FILE_OBJECT from the target handle instead which removes this issue (I believe).

So instead I looked at racing the writing of the cache EA with the signature verification. If you could rewrite the file between the kernel verifying the signature of the file and the writing of the kernel EA you could ensure your USN journal entries from the writes are flushed through before hand and so doesn’t cause the EA to be purged. The kernel code calls FsRtlKernelFsControlFile with FSCTL_WRITE_USN_CLOSE_RECORD to force this flush just before writing the EA so that should work. 

The question is can you write to the file while you’re doing this? There’s no locking taking place on the file from what I could tell. There is a check for the target file being opened with FILE_SHARE_WRITE (the check for FileObject->SharedWrite) but that’s not the same as the file handle already being writable. So it looks like it’s possible to write to the file.

The final question is whether there’s a time period between signature verification and applying the EA that we can exploit? Turns out CI maps the file as a read only section and calls HashKComputeImageHash to generate the hash once. The code then proceeds to lookup the hash inside a catalog (presumably unless the file has an embedded signature). Therefore there's a clear window of time between the validation and the setting of the kernel EA to write.

The final piece of the puzzle is how to win that race reliably. The key is the validation against the catalog files. We can use an exclusive oplock to block the kernel opening the catalog file temporarily, which crucially happens after the target file has already been hashed. By choosing a catalog we know the kernel will check we can get a timing signal, modify the target file to be an unsigned, untrusted file then release the oplock and let the kernel complete the verification and writing of the cache. 

Almost all files on a locked down system such as Win10S are Microsoft Platform signed and so end up in catalogs such as Microsoft-Windows-Client-Features-Package. This seems like a hot-path file which might always be opened by the kernel and so couldn’t be exploited for an oplock. However another useful feature now comes into play, the fact that there’s also an EA which can specify a hint name for the catalog the file is signed in. This is called $CI.CATALOGHINT and so isn’t a kernel EA which means we can set it. It contains a UTF8 encoded file name (without path information). Importantly while CI will check this catalog first, if it can’t find the hash in that catalog it continues searching everything else, so we can pick a non-hot-path catalog (such as Adobe’s Flash catalogs) which we can oplock on, do the write then release and the verification will find the correct real catalog instead.  I don’t think you need to do this, but it makes it considerably more convenient.

Note that to exploit this you’d likely need executable code already running, but we already know there’s multiple DG bypasses and things like Office on Win10S can run macros. Or this could be used from shellcode as I can’t see any obvious limitation on exploiting this from a sandbox as long as you can write a file to an NTFS drive with the USN Change Journal enabled. Running this once would give you an executable or a DLL which bypasses the CI policies, so it could be used as a stage in an attack chain to get arbitrary code executing on a DG system.

In theory it think this would also allow you to specify the signing level for an untrusted file which would allow the DLL to be loaded inside a PPL service so you could use this on a vanilla system to try and attack the kernel through PPL’s such as CSRSS as an administrator. I don’t know how long the cache is valid for, but it’s at least a day or two and might only get revoked if you update your system or replace the file.

Proof of Concept:

I’ve provided a PoC as a C# project. It will allow you to “cache sign” an arbitrary executable. If you want to test this on a locked down system such as Win10S you’ll need to sign the PoC (and the NtApitDotNet.dll assembly) so it’ll run. Or use it via one of my .NET based DG bypasses, in that case you can call the POC.Exploit.Run method directly. It copies notepad to a file, attempts to verify it but uses an oplock to rewrite the contents of the file with the untrusted file before it can set the kernel EA.

1) Compile the C# project. It will need to grab the NtApiDotNet v1.0.8 package from NuGet to work.
2) Execute the PoC passing the path to an unsigned file and to the output  “cache signed” file, e.g. poc unsigned.exe output.exe
3) You should see it print the signing level, if successful.
4) You should not be able to execute the unsigned file, bypassing the security policy enforcement.

NOTE: If it prints an exception then the exploit failed. The opened catalog files seemed to be cached for some unknown period of time after use so if the catalog file I’m using for a timing signal is already open then the oplock is never broken. Wait a period of time and try again. Also the output file must be on to a NTFS volume with the USN Change Journal enabled as that’s relied upon by the signature level cache code. Best to do it to the boot drive as that ensures everything should work correctly.

Expected Result:
Access denied or at least an error setting the cached signing level.

Observed Result:
The signing level cache is applied to the file with no further verification. You can now execute the file as if it was signed with valid Microsoft signature.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse
or a patch has been made broadly available, the bug report will become
visible to the public.




Found by: forshaw

### Windows Defender: Controlled Folder Bypass through UNC Path 




Windows Defender: Controlled Folder Bypass through UNC Path
Platform: Windows 10 1709 + Antimalware client version 4.12.16299.15
Class: Security Feature Bypass

Summary: You can bypass the controlled folder feature in Defender in Windows 10 1709 using a local UNC admin share.

Description:

It was hard not to just blog about this issue, as it’s so obvious and you must known about already, but I thought better of it. I’m sure it wouldn’t help my efforts to mend our fractured relationship :-)

Controlled Folder access seems to be based on a blacklist, which is fine as far as it goes. I didn’t bother to dig too deeply but I’d assume you’re using a filter driver, when you get a hit in the blacklist you reduce the access rights down to a set of read-only rights then return to the caller. This prevents a malicious application deleting or modifying the file because it doesn’t have the access rights to do so. Therefore it then becomes a task of finding a way of accessing the protected file which circumvents the blacklist.

The obvious one for me to try was local UNC admin share, which goes over between the SMB client and SMB server drivers. And this works just fine to open the target file for write/delete access and therefore circumvent the controlled folders feature. As in if you want to access c:\protected\file.txt you open \\localhost\c$\protected\file.txt. While you can only do this as an unsandboxed user you wouldn’t be able to access the file from a sandbox anyway. I did try a few others just to see such as mount points and hardlinks and those seem to be protected as far as I could tell in my limited efforts.

As I said I didn’t look too hard but it would be reasonable to assume as to why this works:

* The actual file is opened in the System process which it likely to be trusted
* The path the filter driver actually sees is the UNC path which isn’t in the blacklist.

You can “fix” this by adding the UNC path to the list of protected folders, however you’ve got so many ways of bypassing it. For example if you block \\localhost\c$\... you can bypass with \\127.0.0.1\c$\... or the real fun one of IPv6 localhost which has many potential representations such as 0::0:0:1 and ::1 etc. You could probably also set up a DNS host which resolves to localhost and just have completely random subdomains. So I’m not sure how you’d fix it, perhaps that’s why it works as it was too hard?

While I understand the rationale for this feature, to leave such a large hole (and then brag about how awesome it is) is a perfect demonstration of the AV fallacy that it blocks everything as long as no one actually tries to bypass the protection. Perhaps some better security testing before shipping it might have been in order as if I can find it so can the Ransomware authors, it wouldn’t take them long to adapt, and then you’d end up with egg on your face.

Also while it’s not a security issue it seems if you open a file and request MAXIMUM_ALLOWED you’d normally get SYNCHRONIZE access. However when the file is in a controlled location you don’t, you only get FILE_GENERIC_READ and SYNCHRONIZE is missing. While you can still get SYNCHRONIZE if you explicitly ask for it (so calling CreateFile should be okay) if you’re calling the native API you won’t. I could imagine this might break some drivers if they relied on being able to SYNCHRONIZE on a MAXIMUM_ALLOWED handle. Perhaps you can pass this along?

Proof of Concept:

I’ve provided a PoC as a C# project. You could easily do this with PowerShell or CMD as they don’t seem to be trusted but this proves it’s not some fluke due to a MS binary.

1) Compile the C# source.
2) Enable Controlled Folder Access option with default configuration.
3) Create a file in a protected location such as the user’s Desktop folder with an approved application such as explorer.
4) Run the poc passing the local filesystem path, e.g. c:\users\user\desktop\file.txt
5) Run the poc passing a local UNC admin share path e.g. \\localhost\c$\users\user\desktop\file.txt

Expected Result:
Controlled folder access should block both file paths.

Observed Result:
Defender blocks the direct path but doesn’t block the one via UNC and the protected file is deleted.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.




### Found by: forshaw

Intel: Content Protection HECI Service Type Confusion EoP 

CVE-2017-5717


Intel Content Protection HECI Service Type Confusion EoP
Platform: Tested on Windows 10, service version 9.0.2.117
Class: Elevation of Privilege

Summary:
The Intel Content Protection HECI Service exposes a DCOM object to all users and most sandboxes (such as Edge LPAC and Chrome GPU). It has a type confusion vulnerability which can be used to elevate to SYSTEM privileges.

Description:

The Intel Content Protection HECI Service runs as LocalSystem and hosts a DCOM service. The main function is StartIo which takes an input variant and returns a variant. Based on what it’s trying to do I’d assume the input variant is supposed to be a byte array, however it contains a bug.

The vulnerable code is roughly:

HRESULT StartIo(VARIANT In, VARIANT* Out) {
   CComSafeArray<char> array;
   array::CopyFrom(In.parray);
   // Work with array
   ...
}

The issue here is that the In variant is used as a SAFEARRAY without checking that the VARIANT contains a SAFEARRAY. This leads to type confusion, for example a caller could pass VT_UI4 integer with any value they like and this code would interpret that integer as a pointer to a SAFEARRAY structure. This might seem to be only an arbitrary read issue, however the copy of the safe array can be made to execute arbitrary memory. If you point the type confused pointer at a block of memory which looks like a IUnknown array then when copying the array it will try and add a reference to each COM object in the array. This causes a VTable dispatch to AddRef which if carefully crafted should get arbitrary code execution.

The call to CopyFrom does verify that the variant type is VT_UI1 (a byte array) however you can set some feature flags such as FADF_UNKNOWN which will force a call to IUnknown::AddRef on the elements of the array without changing the supposed variant type. Also you don’t need to guess the allocation address for the fake safearray as you can use a byte length BSTR which contains arbitrary data. The BSTR length field and the SAFEARRAY variant field lines up so as long as the lower 16 bits of the length is set to 17 (which is VT_UI1) it passes the checks and reads out the arbitrary contents from the allocated BSTR.

The really bad thing about this service is not only is it intentionally designed to be accessible from even a heavily restrictive sandbox such as Edge LPAC but it runs with full LocalSystem privileges. While on Win10 CFG might make it harder to exploit, on Win7 you don’t have any such protection. Also the call is done inside an exception handler so even if the wrong address is chosen the service won’t crash (except for fast fail such as CFG).

The following is an example crash when sending a fake safe array to the service (with just a dummy address of 0x18181818 as the IUnknown memory location).

(1110.1188): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=18181818 ebx=001e6290 ecx=18181818 edx=00209390 esi=11d41024 edi=18181818
eip=18181818 esp=0126efc4 ebp=0126efec iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
18181818 1818            sbb     byte ptr [eax],bl          ds:002b:18181818=18
0:003> k
 # ChildEBP RetAddr  
WARNING: Frame IP not in any known module. Following frames may be wrong.
00 0126efc0 74f740fb 0x18181818
01 0126efec 74f73e42 OLEAUT32!SafeArrayCopyData+0x21b
02 0126f018 010335d3 OLEAUT32!SafeArrayCopy+0x182
03 0126f030 01034e1b IntelCpHeciSvc+0x135d3
04 0126f118 750326e0 IntelCpHeciSvc+0x14e1b
05 0126f144 74ff4fc2 RPCRT4!Invoke+0x34
06 0126f598 7525555e RPCRT4!NdrStubCall2+0x452
07 0126f5e4 74f70706 combase!CStdStubBuffer_Invoke+0xde [onecore\com\combase\ndr\ndrole\stub.cxx @ 1449] 
08 0126f614 75300c48 OLEAUT32!CUnivStubWrapper::Invoke+0x136
09 (Inline) -------- combase!InvokeStubWithExceptionPolicyAndTracing::__l6::<lambda_1ba7c1521bf8e7d0ebd8f0b3c0295667>::operator()+0x4e [onecore\com\combase\dcomrem\channelb.cxx @ 1824] 
0a 0126f668 75303621 combase!ObjectMethodExceptionHandlingAction<<lambda_1ba7c1521bf8e7d0ebd8f0b3c0295667> >+0xa8 [onecore\com\combase\dcomrem\excepn.hxx @ 91] 
0b (Inline) -------- combase!InvokeStubWithExceptionPolicyAndTracing+0x8e [onecore\com\combase\dcomrem\channelb.cxx @ 1822] 
0c 0126f78c 75307330 combase!DefaultStubInvoke+0x221 [onecore\com\combase\dcomrem\channelb.cxx @ 1891] 
0d (Inline) -------- combase!SyncStubCall::Invoke+0x22 [onecore\com\combase\dcomrem\channelb.cxx @ 1948] 
0e (Inline) -------- combase!SyncServerCall::StubInvoke+0x22 [onecore\com\combase\dcomrem\servercall.hpp @ 779] 
0f (Inline) -------- combase!StubInvoke+0x287 [onecore\com\combase\dcomrem\channelb.cxx @ 2173] 
10 0126f90c 7530009b combase!ServerCall::ContextInvoke+0x440 [onecore\com\combase\dcomrem\ctxchnl.cxx @ 1541] 
11 (Inline) -------- combase!CServerChannel::ContextInvoke+0x669 [onecore\com\combase\dcomrem\ctxchnl.cxx @ 1437] 
12 (Inline) -------- combase!DefaultInvokeInApartment+0x669 [onecore\com\combase\dcomrem\callctrl.cxx @ 3532] 
13 (Inline) -------- combase!ClassicSTAInvokeInApartment+0x669 [onecore\com\combase\dcomrem\callctrl.cxx @ 3296] 
14 0126f9ac 75302b39 combase!AppInvoke+0x8bb [onecore\com\combase\dcomrem\channelb.cxx @ 1604] 
15 0126fb3c 7530ff85 combase!ComInvokeWithLockAndIPID+0x599 [onecore\com\combase\dcomrem\channelb.cxx @ 2722] 
16 0126fb98 7531056b combase!ComInvoke+0x1c5 [onecore\com\combase\dcomrem\channelb.cxx @ 2242] 
17 (Inline) -------- combase!ThreadDispatch+0x83 [onecore\com\combase\dcomrem\chancont.cxx @ 421] 
18 0126fbd8 76b12b5b combase!ThreadWndProc+0x21b [onecore\com\combase\dcomrem\chancont.cxx @ 741] 
19 0126fc04 76b050f3 USER32!_InternalCallWinProc+0x2b
1a 0126fcec 76b04a82 USER32!UserCallWinProcCheckWow+0x2d3
1b 0126fd60 76b04850 USER32!DispatchMessageWorker+0x222
1c 0126fd6c 010364e1 USER32!DispatchMessageW+0x10
1d 0126fda0 01037039 IntelCpHeciSvc+0x164e1
1e 0126fda8 0103e562 IntelCpHeciSvc+0x17039
1f 0126fde0 0103e5ec IntelCpHeciSvc+0x1e562
20 0126fdec 76928744 IntelCpHeciSvc+0x1e5ec
21 0126fe00 770a582d KERNEL32!BaseThreadInitThunk+0x24
22 0126fe48 770a57fd ntdll!__RtlUserThreadStart+0x2f
23 0126fe58 00000000 ntdll!_RtlUserThreadStart+0x1b

Proof of Concept:

I’ve provided a PoC as a VS project which you can run which will cause the service to access invalid memory. Note that you’ll need a debugger attached to IntelCpHeciSvc.exe as the RPC/DCOM dispatch will swallow the exception, it doesn’t crash the service. The Poc builds a fake SAFEARRAY structure and passes it as a BSTR to the service which gets interpreted as a pointer to a SAFEARRAY. Ultimately it tries to copy the array and will call AddRef on elements of the array.

1) Attach a debugger to IntelCpHeciSvc.exe
2) Compile and run the provided poc.

Expected Result:
Sending the fake SAFEARRAY should fail.

Observed Result:
The service tries to execute invalid memory at 0x18181818 (or at least crashes on an invalid memory location).

This bug is subject to a 90 day disclosure deadline. After 90 days elapse
or a patch has been made broadly available, the bug report will become
visible to the public.




### Found by: forshaw

Windows: Local XPS Print Spooler Sandbox Escape 




Windows: Local XPS Print Spooler Sandbox Escape
Platform: Windows 10 1703 and 1709 (not tested Windows 7 or 8.x)
Class: Elevation of Privilege

Summary:

The local print spooler can be abused to create an arbitrary file from a low privilege application including one in an AC as well as a typical Edge LPAC CP leading to EoP.

Description:

When creating an XPS print job it's possible to specify the destination file in the DOC_INFO_1 structure passed to StartDocPrinter. When you call WritePrinter to write to the new printer job the privileged printer spooler service impersonates the caller and ensures that they can write to the target. This should ensure that a sandboxed user can't write to a location they don't have access to normally. Unfortunately the spooler then deletes this file it's created under impersonation and then calls NSecurityLibrary::ElevateIntegrityLevelIfLow to increase the IL of caller's token to Medium level if the token is current Low IL. In a naive sandbox such as IE PM this results in the actual file being written as at Medium IL which would be sufficient for writing to any user controlled location such as the Startup folder. However in an AC sandbox you'd assume this wouldn't help as the AC would still be enforced even if the IL of the token was raised. It seems not, if code raises the IL of the AC token to medium (which requires SeTcbPrivilege) then the kernel also removes all traces of the AC, leaving the final token a normal medium IL user token again. Therefore in both the naive and AC cases there exists a TOCTOU attack where you can get the sandboxed token to write to a folder you control then redirect the write to another location once the token IL is raised.

The simplest way of doing this would be your standard symbolic link attacks, fortunately Windows has mitigated all the easy ways of doing such an attack. Unfortunately there's a bug in the handling of NtImpersonateAnonymousToken when running in AC which allows a symlink attack in this specific case. I've submitted the bug in NtImpersonateAnonymousToken as a separate issue. Of course there's no reason to believe that there's no other way of exploiting this issue given enough effort without the bug in NtImpersonateAnonymousToken.

To exploit do the following:

1) Create a fake destination directory in a AC writable directory such as Temp. e.g. if you want to write to c:\users\user\desktop\hello.txt create %TEMP%\users\user\desktop.
2) Use bug in NtImpersonateAnonymousToken to impersonate the non-AC token and create a new C: drive symlink in the anonymous user's drive map pointing at the temp directory. Note that as this is created inside a sandbox a non-sandboxed caller will NOT follow the symlink.
3) Build a native NT path in Win32 form to the target path via the anonymous token's device map directory and pass to StartDocPrinter in DOC_INFO_1. e.g. \\?\GLOBALROOT\Sessions\0\DosDevices\00000000-000003E6\C:\Users\user\desktop\hello.txt
4) Create the "fake" target file in the temp directory and put an exclusive oplock on it.
5) Call WritePrinter in another thread, in original thread wait for the oplock to complete. The open in the print spooler will follow the symlink in this case as it's impersonating the sandboxed token.
6) Delete the symlink and break the oplock, this allows the spooler to continue.
7) The spooler now impersonates the medium user token and tried to open the path. The C: symlink created in 2 now no longer exists, however as we're using a device map directory then the global devicemap fallback will kick in so that the spooler sees the global C: drive.
8) The spooler writes arbitrary data to the new target file outside of the sandboxed area.

I really don't get why the token is elevated before writing the file. There is a mode where if you don't specify a path then the spooler will write the file to the local documents directory. As the sandboxed application has no control of the path it at least makes some sense to elevate to allow the file to be written but when writing an explicit path it seems unnecessary. Note that this also works from LPAC, at least as implemented for Edge CP's. This is because the ALPC port of the spooler has an ACE with the “lpacPrinting” capability which is in the list of capabilities in most (all?) CP's for Edge. I also note that WDAG supports writing XPS files, but I don’t have the time to work out the details of how WDAG works right now to see if it would also be vulnerable.

Proof of Concept:

I’ve provided a PoC as a C# project. The PoC will drop the file hello.txt to the current user’s desktop with arbitrary contents. The PoC will respawn itself as the Microsoft Edge AC and then execute the exploit. You must run this as a UAC split token admin. Note that this ISN’T a UAC bypass, just that a split-token admin has a trivial way of getting a non-AC token by requesting the linked token. The PoC will execute just using a normal AC, to test with LPAC pass the executable any argument you like, the LPAC capabilities are copied from an Edge CP so should be representative of what’s available in real life. It seems on some systems the .NET framework directory has an incorrect DACL which results in the LPAC mode failing. A fresh install of 1709 should work though.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work. Ensure the main executable and DLLs are in a user writable location (this is needed to tweak the file permissions for AC).
2) Execute the PoC as normal user level split-token admin.
3) Once complete a dialog should appear indicating the operation is Done.

Expected Result:
Writing to a file outside of a sandbox accessible directory should fail.

Observed Result:
The file hello.txt is created in the current user’s desktop directory with arbitrary contents.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.



### Found by: forshaw

Windows: NTFS Owner/Mandatory Label Privilege Bypass EoP 

CVE-2018-0748


Windows: NTFS Owner/Mandatory Label Privilege Bypass EoP
Platform: Windows 10 1709 not tested 8.1 Update 2 or Windows 7
Class: Elevation of Privilege

Summary:
When creating a new file on an NTFS drive it’s possible to circumvent security checks for setting an arbitrary owner and mandatory label leading to a non-admin user setting those parts of the security descriptor with non-standard values which could result in further attacks resulting EoP.

Description:

The kernel limits who can arbitrarily set the Owner and Mandatory Label fields of a security descriptor. Specifically unless the current token has SeRestorePrivilege, SeTakeOwnershipPrivilege or SeRelabelPrivilege you can only set an owner which is set in the current token (for the label is can also be less than the current label). As setting an arbitrary owner in the token or raising the IL is also a privileged operation this prevents a normal user from setting these fields to arbitrary values.

When creating a new file on an NTFS volume you can specify an arbitrary Security Descriptor with the create request and it will be set during the creation process. If you specify an arbitrary owner or label it will return an error as expected. Looking at the implementation in NTFS the function NtfsCreateNewFile calls NtfsAssignSecurity which then calls the kernel API SeAssignSecurityEx. The problem here is that SeAssignSecurityEx doesn’t take an explicit KPROCESSOR_MODE argument so instead the kernel takes the current thread’s previous access mode. The previous mode however might not match up with the current assumed access mode based on the caller, for example if the create call has been delegated to a system thread.

A common place this mode mismatch occurs is in the SMB server, which runs entirely in the system process. All threads used by SMB are running with a previous mode of KernelMode, but will create files by specifying IO_FORCE_ACCESS_CHECK so that the impersonated caller identity is used for security checks. However if you specify a security descriptor to set during file creation the SMB server will call into NTFS ending up in SeAssignSecurityEx which then thinks it’s been called from KernelMode and bypasses the Owner/Label checks.

Is this useful? Almost certainly there’s some applications out there which use the Owner or Label as an indicator that only an administrator could have created the file (even if that’s not a very good security check). For example VirtualBox uses it as part of its security checks for whether a DLL is allowed to be loaded in process (see my blog about it <a href="https://googleprojectzero.blogspot.com.au/2017/08/bypassing-virtualbox-process-hardening.html" title="" class="" rel="nofollow">https://googleprojectzero.blogspot.com.au/2017/08/bypassing-virtualbox-process-hardening.html</a>) so I could imagine other examples including Microsoft products. Another example is process creation where the kernel checks the file's label to determine if it needs to drop the IL on the new process, I don't think you can increase the IL but maybe there's a way of doing so.

Based on the implementation this looks like it would also bypass the checks for setting the SACL, however due to the requirement for an explicit access right this is blocked earlier in the call through the SMBv2 client. I’ve not checked if using an alternative SMBv2 client implementation such as SAMBA would allow you to bypass this restriction or whether it’s still blocked in the server code.

It’s hard to pin down which component is really at fault here. It could be argued that SeAssignSecurityEx should take a KPROCESSOR_MODE parameter to determine the security checks rather than using the thread’s previous mode. Then again perhaps NTFS needs to do some pre-checking of it’s own? And of course this wouldn’t be an issue if the SMB server driver didn’t run in a system thread. Note this doesn’t bypass changing the Owner/Label of an existing file, it’s only an issue when creating a new file.

Proof of Concept:

I’ve provided a PoC as a C# source code file. You need to compile it first. It will attempt to create two files with a Security Descriptor with the Owner set to SYSTEM. 

1) Compile the C# source code file.
2) Execute the PoC as a normal user or at least a filtered split-token admin user.

Expected Result:
Both file creations should fail with the same error when setting the owner ID.

Observed Result:
The first file which is created directly fails with an error setting the owner ID. The second file which is created via the C$ admin share on the local SMB server succeeds and if the SD is checked the owner is indeed set to SYSTEM.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse
or a patch has been made broadly available, the bug report will become
visible to the public.




Found by: forshaw

### CVE-2018-0751


Windows: NtImpersonateAnonymousToken AC to Non-AC EoP
Platform: Windows 10 1703 and 1709
Class: Elevation of Privilege

Summary:
The check for an AC token when impersonating the anonymous token doesn’t check impersonation token’s security level leading to impersonating a non-AC anonymous token leading to EoP.

Description:


There's a missing check for impersonation level in NtImpersonateAnonymousToken when considering if the caller is currently an AC. This results in the function falling into the restricted token case if the caller is impersonating a non AC token at identification or below. Some example code is shown highlighting the issue.

SeCaptureSubjectContext(&ctx);
PACCESS_TOKEN token = ctx.ClientToken;
if (!ctx.ClientToken) <--- Should check the token's impersonation level here, and fallback to the PrimaryToken.
  token = ctx.PrimaryToken;
if (token->Flags & 0x4000) {
  // ... Impersonate AC anonymous token.
} else if (!SeTokenIsRestricted(PsReferencePrimaryToken())) { <-- AC PrimaryToken isn't restricted so this check passes
  // ... Impersonate normal anonymous token.
}

For example when using a split-token admin you can trivially get the linked token and impersonate that. As an AC token isn't restricted this results in impersonating the normal anonymous token which is arguably less restricted than the AC token in some cases and is certainly less restricted than the anonymous AC token which is normally created using SepGetAnonymousToken. For example you can open objects with a NULL DACL if you can traverse to them or open devices which would normally need the special AC device object flag for traversal across the object namespace. You can also access the anonymous token's device map and modify it, potentially leading to bypass of symbolic link protections in certain cases. 

Proof of Concept:

I’ve provided a PoC as a C# project. The PoC will respawn itself as the Microsoft Edge AC and then execute the exploit. You must run this as a UAC split token admin. Note that this ISN’T a UAC bypass, just that a split-token admin has a trivial way of getting a non-AC token by requesting the linked token.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work. Ensure the main executable and DLLs are in a user writable location (this is needed to tweak the file permissions for AC).
2) Execute the PoC as normal user level split-token admin.
3) Once complete a dialog should appear indicating the operation is a success.

Expected Result:
The AC anonymous token is impersonated, or at least an error occurs.

Observed Result:
The Non-AC anonymous token is impersonated.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.



Found by: forshaw

### CVE-2018-0752


Windows: NtImpersonateAnonymousToken LPAC to Non-LPAC EoP
Platform: Windows 10 1703 and 1709 (not tested Windows 8.x)
Class: Elevation of Privilege

Summary:
When impersonating the anonymous token in an LPAC the WIN://NOAPPALLPKG security attribute is ignored  leading to impersonating a non-LPAC token leading to EoP.

Description:

When running in LPAC the WIN://NOAPPALLPKG attribute is used to block the default use of the ALL APPLICATION PACKAGES sid. When impersonating the anonymous token this attribute isn't forwarded on to the new token in SepGetAnonymousToken. This results in being able to impersonate a "normal" AC anonymous token which could result in getting more access to the system (such as anything which is marked as ANONYMOUS LOGON and ALL APPLICATION PACKAGES but not ALL RESTRICTED APPLICATION PACKAGES or a specific capability SID). 

Proof of Concept:

I’ve provided a PoC as a C# project. The PoC will respawn itself as the Microsoft Edge LPAC and then execute the exploit. 

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work. Ensure the main executable and DLLs are in a user writable location (this is needed to tweak the file permissions for AC).
2) Execute the PoC as normal user
3) Once complete a dialog should appear indicating the operation is a success.

Expected Result:
The anonymous token is an LPAC.

Observed Result:
The anonymous token is a normal AC.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.



Found by: forshaw
### CVE-2018-0749


Windows: SMB Server (v1 and v2) Mount Point Arbitrary Device Open EoP
Platform: Windows 10 1703 and 1709 (seems the same on 7 and 8.1 but not extensively tested)
Class: Elevation of Privilege

Summary:

The SMB server driver (srv.sys and srv2.sys) don't check the destination of a NTFS mount point when manually handling a reparse operation leading to being able to locally open an arbitrary device via an SMB client which can result in EoP.

Description:

Note before I start event though this involves SMB this is only a local issue, I don't know of anyway to exploit this remotely without being able to run an application on the local machine.

NTFS mount points are handled local to the SMB server so that the client does not see them. This is different from NTFS symbolic links which are passed back to the client to deal with. In order to handle the symbolic link case the server calls IoCreateFileEx from Smb2CreateFile passing the IO_STOP_ON_SYMLINK flag which results in the IoCreateFileEx call failing with the STATUS_STOPPED_ON_SYMLINK code. The server can then extract the substitution path from the reparse pointer buffer and either pass the buffer to the client if it's a symbolic link or handle it if it's a mount point. 

The way the server handles a symbolic link is to recall IoCreateFileEx in a loop (it does check for a maximum iteration count although I'd swear that's a recent change) passing the new substitute path. This is different to how the IO manager would handle this operation. In the IO manager's case the reparse operation is limited to a small subset of device types, such as Disk Volumes. If the new target isn't in the small list of types then the reparse will fail with an STATUS_IO_REPARSE_DATA_INVALID error. However the SMB server does no checks so the open operation can be redirected to any device. This is interesting due to the way in which the device is being opened, it's in a system thread and allows a caller to pass an arbitrary EA block which can be processed by the device create handler. 

One use for this is being able to the spoof the process ID and session ID accessible from a named pipe using APIs such as GetNamedPipeClientProcessId. Normally to set these values to arbitrary values requires kernel mode access, which the SMB driver provides. While you can open a named pipe via SMB anyway in that case you can't specify the arbitrary values as the driver provides its own to set the computer name accessible with GetNamedPipeClientComputerName. I've not found any service which uses these values for security related properties.
 
Note that both SMBv1 and SMBv2 are vulnerable to the same bug even the code isn't really shared between them.

Proof of Concept:

I’ve provided a PoC as a C# project. It creates a mount point to \Device and then tries to open the CNG driver directly and via the local share for the drive. 

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Execute the PoC as a normal user.

Expected Result:
Both direct and via SMB should fail with STATUS_IO_REPARSE_DATA_INVALID error.

Observed Result:
The direct open fails with STATUS_IO_REPARSE_DATA_INVALID however the one via SMB fails with STATUS_INVALID_INFO_CLASS which indicates that the CNG driver was opened.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.




Found by: forshaw
### CVE-2018-0822


Windows: Global Reparse Point Security Feature Bypass/Elevation of Privilege
Platform: Windows 10 1709 (functionality not present prior to this version)
Class: Security Feature Bypass/Elevation of Privilege

Summary: It’s possible to use the new Global Reparse Point functionality introduced in Windows 10 1709 to bypass the existing sandbox limitations of creating arbitrary file symbolic links.

Description:

Windows 10 introduced mitigations to prevent the abuse of various types of symbolic links when a process is running in a sandbox. This is a combination of outright blocking of the functionality (such as in the case of Registry Key symlinks) to doing checks on the target location so that the sandbox user can write to the location (in the case of Mount Points). 

Fall Creator’s Update has introduced a new defined reparse tag, the Global Reparse Point (value 0xA0000019) which I assume is for Silo’s where a symlink can be added into the Silo’s visible namespaces which actually redirects to the global namespace. One user of this is the named pipe file system. It seems that nothing prevents you creating this type of reparse point on an NTFS volume, it doesn’t get checked by the kernel for the sandbox mitigation and because the NTFS driver ignores anything which isn’t a mount point or a ntfs symbolic link it will also not check for the SeCreateSymbolicLinkPrivilege. This symbolic link type works to reparse to any file type so you can create either a file or directory symbolic link. The reparse buffer is basically the same as the normal symbolic link one, but with a different tag. In fact strangely the named pipe file system passes back a buffer with the normal symbolic link tag but with the global reparse tag in the data structure passed back to IopParseDevice.

Outside of the behavior in sandboxes you might want to check that the reparse buffer is correctly verified. Normally the NTFS driver checks the structure of a reparse buffer using FsRtlValidateReparsePointBuffer but that function doesn’t know about the new reparse tag, so you could end up with completely untrusted data being passed into the object manager (NPFS synthesizes the reparse buffer so normally it would be trusted). I’ve not checked if you could trivially BSoD the machine through this approach.

Note that while NTFS symbolic links can be created without privileges in developer mode this bypass also allows a normal user to create them without developer mode being enabled so also acts as an EoP.

Proof of Concept:

I’ve provided a PoC as a C# project. 

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Run the poc as Low IL or an in AC passing on the command line the name of the symlink file to create and a target path. For example ‘poc c:\test\hello c:\windows’ will create a symlink ‘hello’ pointing at ‘c:\windows’. Make sure the destination name can be written to as the sandboxed user.
3) Open the symbolic link as a normal privileged user to see if the reparse target is followed.

Expected Result:
The creation of the symlink should fail with an error.

Observed Result:
The symlink is created, is valid and can be used to access the target.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.




Found by: forshaw
### CVE-2018-0823


Windows: NPFS Symlink Security Feature Bypass/Elevation of Privilege/Dangerous Behavior
Platform: Windows 10 1709 (functionality not present prior to this version)
Class: Security Feature Bypass/Elevation of Privilege/Dangerous Behavior

Summary: It’s possible to create NPFS symlinks as a low IL or normal user and the implementation doesn’t behave in a similar manner to other types of Windows symlinks leading to dangerous behavior or EoP.

Description:

Windows 10 1709 introduced a new symlink feature to NPFS which is accessible from a FSCTL. From what I can see the implementation has a number of security issues which concern me:

1) Creation of symbolic links is only limited to a user which can open the root named pipe device. I.e. \Device\NamedPipe. This users which can open the device includes restricted tokens with the RESTRICTED SID and Low IL tokens.
2) Accessing a symlink results in the NPFS driver synthesizing a NTFS symlink reparse point which is passed back to the object manager. This allows the symlink to reparse to different devices. This is presumably by design but it’s dangerous behavior.
3) Opening a symlink doesn’t respect the FILE_OPEN_REPARSE_POINT which could lead to some unusual behavior.

The fact that you can create the symlink as a lower privileged user is bad enough, although I don’t believe it can be done from an AC so maybe you don’t care about it. But the other two issues are examples of dangerous behavior which _will_ come back to bite you at some point in the future.

Let’s take point 2 as an example, up to this point NPFS hasn’t had the concept of symbolic links. Sure you could drop an appropriate object manager symlink somewhere and get a caller to follow it but you’d need to be able to influence the callers path or their DOS device directory. With this if a privileged caller is expecting to open a named pipe, say \\.\pipe\ABC then ABC could actually be a symbolic link to a normal file. If the caller then just writes data to the pipe expecting it to be a stream they could actually be writing data into a file which might result in EoP. Basically I see it’s a case of when not if that a EoP bug is found which abuses this behavior. 

Also, there’s no way I know of for detecting you’re opening a symbolic link. For example if you open the target with the FILE_OPEN_REPARSE_POINT flag it continues to do the reparse operation. Due to creating a normal NTFS symbolic link this might also have weird behavior when a remote system accessed a named pipe, although I’ve not tested that. 

Overall I think the behavior of the implementation has the potential for malicious use and should be limited to privileged users. I don’t know it’s original purpose, perhaps it’s related to Silos (there is a flag to make a global symlink) or it’s to make it easier to implement named pipes in WSL, I don’t know. If the purpose is just to symlink between named pipes then perhaps only allow a caller to specify the name relative to the NPFS device rather than allowing a full object path.

Proof of Concept:

I’ve provided a PoC as a C# project. The PoC will create a symlink called ABC which points to notepad.exe. It will check the file file it opens via the symlink matches the file opened directly.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Run the poc as Low IL (using say psexec).

Expected Result:
The creation of the symlink should fail with an error.

Observed Result:
The symlink is created, is valid and the poc printed ‘Success’ as it’s opened the copy of notepad.exe via the symlink.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.



Found by: forshaw
### CVE-2018-0826


Windows: StorSvc SvcMoveFileInheritSecurity Arbitrary File Creation EoP
Platform: Windows 10 1709 (not tested earlier versions)
Class: Elevation of Privilege

Summary: The SvcMoveFileInheritSecurity RPC method in StorSvc can be used to move an arbitrary file to an arbitrary location resulting in elevation of privilege.

Description:

I was reading Clément Rouault & Thomas Imbert excellent PacSec’s slides on ALPC+RPC issues and they highlighted the SvcMoveFileInheritSecurity method used to exploit the ALPC bug CVE-2017-11783. The function impersonates the user and calls MoveFileEx to move the file to a new destination, then reverts the impersonation and tries to reset the security descriptor of the new file so that it matches the inheritable permissions. The ALPC bug in CVE-2017-11783 has apparently been fixed but the behavior of the SvcMoveFileInheritSecurity has not been modified as far as I can tell.

The main problem occurs if the call to SetNamedSecurityInfo fails, in that case the code tries to move the file back to its original location, however it does reassert the impersonation. This probably makes sense because it’s possible to have a file/directory which you can open for DELETE but without the rights to create a new file in the same directory. In the case the original move would succeed but the revert would fail. However there’s a TOCTOU issue in that the original path might have been replaced with a mount point which redirects the revert to a totally arbitrary location while running at SYSTEM. The exploit controls both the name and the contents of the file so this would be a trivial privilege escalation.

It’s possible to cause SetNamedSecurityInfo to fail just by adding a Deny ACE to the file for SYSTEM. This will cause the function to get ERROR_ACCESS_DENIED and the revert will take place. By placing an oplock on the original file open we can switch in a mount point and always win the race condition.

Ideally all operations should take place under user impersonation, but if that was the case there’d be no point in doing it in a SYSTEM service to begin with. Note that there’s a second issue specifically with SetNamedSecurityInfo which I’ve sent as a separate issue, just in case it gets missed.

Proof of Concept:

I’ve provided a PoC as a C++ project. It will abuse the SvcMoveFileInheritSecurity method to create the file test.txt in the windows folder.

1) Compile the C++ project.
2) Execute the PoC as a normal user.

Expected Result:
The file reversion fails trying to copy the file back to its original location.

Observed Result:
The file is reverted which results in the test.txt file being creating in c:\windows.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.




Found by: forshaw

### Windows: StorSvc SvcMoveFileInheritSecurity Arbitrary File Security Descriptor Overwrite EoP 




Windows: StorSvc SvcMoveFileInheritSecurity Arbitrary File Security Descriptor Overwrite EoP
Platform: Windows 10 1709 (not tested earlier versions)
Class: Elevation of Privilege

Summary: The SvcMoveFileInheritSecurity RPC method in StorSvc can be used assign an arbitrary security descriptor to an arbitrary file leading to EoP.

Description:

Note this is a second bug in the same function. I’m submitting it separately just to ensure that the resulting fix doesn't miss this edge case as well.

I was reading Clément Rouault & Thomas Imbert excellent PacSec’s slides on ALPC+RPC issues and they highlighted the SvcMoveFileInheritSecurity method used to exploit the ALPC bug CVE-2017-11783. The function impersonates the user and calls MoveFileEx to move the file to a new destination, then reverts the impersonation and tries to reset the security descriptor of the new file so that it matches the inheritable permissions. The ALPC bug in CVE-2017-11783 has apparently been fixed but the behavior of the SvcMoveFileInheritSecurity has not been modified as far as I can tell.

The problem occurs if SvcMoveFileInheritSecurity is used to move a hardlinked file. It’s possible using the native APIs to hardlink to a file that the user can only read. As long as the directory the link is in grants the user delete file access then even though requesting DELETE fails on the file’s security descriptor it’s granted based on the parent directory. This allows the MoveFileEx call to succeed when being called under impersonation.

If the file is moved to a directory which has inheritable ACEs which would grant the user access then when the server calls SetNamedSecurityInfo it will apply the inherited ACEs onto the file as the API assumes that the parent is the folder the file is currently linked into to, not the location that the file was originally in. As this is performed as SYSTEM this means that any file can be given an arbitrary Security Descriptor which would allow a user to modify it.

Proof of Concept:

I’ve provided a PoC as a C++ project. It will abuse the SvcMoveFileInheritSecurity method to create the file test.txt in the windows folder.

1) Compile the C++ project.
2) Execute the PoC as a normal user passing the path to a file on the system drive on the command line which you want to overwrite the security descriptor.

Expected Result:
The file move fails.

Observed Result:
The target file has had it’s security descriptor rewritten to allow access to everyone.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.



Found by: forshaw

### CVE-2018-0821


Windows: Constrained Impersonation Capability EoP
Platform: Windows 10 1703/1709 (not tested earlier versions)
Class: Elevation of Privilege

Summary: It’s possible to use the constrained impersonation capability added in Windows 10 to impersonate a lowbox SYSTEM token leading to EoP.

Description:

Windows 10 added a new security check during impersonation of a token which relies on an AppContainer capability Constrained Impersonation which allows a LowBox process to impersonate another LowBox token, even if it’s for a different user, as long as it meets certain requirements. Specifically:

- The impersonation token’s session ID is the same as the current process’ session ID
- The impersonation token has the same AC package SID as the process’
- The impersonation token’s capability sids are a subset of the processes

I’d assume that the thoughts around the security of this constrained impersonation capability is preventing an exist lowbox process gaining that capability. However this can be abused from a normal user privilege level by creating a new AC process with the capability. As a normal user it’s possible to create a new lowbox token from an existing one which has any capabilities you like and the package SID can be arbitrary. 

The only limiting factor is getting hold of a suitable token which has the same session ID. This is easy for example in UAC scenarios (including OTS elevation) but of course that’s a UAC bypass. There’s various tricks to get a SYSTEM token but most of the services run in Session 0. However there are a few processes running as SYSTEM but in the same session on a default install of Windows including CSRSS and Winlogon. There’s also the consent process which is part of UAC which is spawned in the user session. Therefore one way to get the token is to try and elevate a process running on a WebDAV share (hosted on localhost) and negotiate the NTLM/Negotiate auth in a similar way to previous issues I’ve reported (e.g. cases 21243 and 21878).

With a SYSTEM token handle it’s now possible to impersonate it as a lowbox from a normal user account. Of course this isn’t a direct privilege escalation as you can’t access administrator resources, however you can find system services which do the wrong thing. One example is code which just checks the Authentication ID of the token and assumes if it’s the SYSTEM ID then it’s trusted. A second example are AC processes which either run as SYSTEM or have tried to lock down themselves, a good example is the UMFD process, resources created by this process have access to SYSTEM as well as the package SID so you could inject code through hijacking a thread or one of the processes named resources. The final example are services which increase the IL of the caller, such as the print spooler bug I reported in case 41850, which you could get an arbitrary write as SYSTEM which gives you direct EoP.

Proof of Concept:

I’ve provided a PoC as a C# project. It implements a WebDAV server on localhost which will require authentication. Any user which tries to open a file on the share will have its token captured. It then uses UAC consent to get a call to the WebDAV server as a system token in the current session. Note that although I’m abusing UAC it’s not a UAC bypass, it’s just a convenient way of getting the token. This would still work in OTS UAC as the token happens before the process is actually executed (which means the password doesn’t have to be entered) so it’s still an issue. Once a suitable token has been captured the PoC spawns a new process in an AC and impersonates the system token on the main thread. It then abuses some functionality which was “fixed” in MS15-10, that it’s possible to open a service with SERVICE_STATUS access rights as long as the caller is SYSTEM. Admittedly this seemed to be a bogus fix as impersonation shouldn’t work like that in RPC, but in this case it doesn’t really matter as we can actually impersonate a SYSTEM token. The PoC stops at the point of getting a valid handle to the service, I’ve not worked out what you can usefully do with that handle, maybe start/stop a service you wouldn’t normally be able to?

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) In an admin command prompt run the command “netsh http add urlacl url=http://127.0.0.1:4444/WebDAV user=Everyone” this is to just allow the PoC to use the HttpListener class which saves me from writing my own HTTP server implementation. You could do it entirely manually and not require this step but it’s just an issue with the  listener classes that you need to add an acl for it, I was just too lazy to write my own.
3) Run the NtlmAuth PoC, it should setup the WebDAV server, start the WebClient service and then start an UAC elevation on the WebDAV server to capture the token. It’ll then run the test binary to open the service.
4) Cancel the UAC elevation prompt. You should now see a message box on the desktop from the test binary saying Success.

Expected Result:
Impersonating the SYSTEM token in a LowBox shouldn’t be possible.

Observed Result:
The test binary is running while impersonating the SYSTEM token. It’s opened a handle to the WebClient service with SERVICE_STATUS access rights.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.




Found by: forshaw

### CVE-2018-0877


Windows: Windows: Desktop Bridge VFS EoP
Platform: Windows 1709 (not tested earlier version)
Class: Elevation of Privilege

Summary: The handling of the VFS for desktop bridge applications can allow an application to create virtual files in system folder which can result in EoP.

Description:
The desktop bridge functionality introduced in Anniversary edition allows an application to set up a virtual file system to redirect access to AppData as well as system folders to reduce the amount of changes needed for a converted Win32 application. Access to AppData is automatic but for system folders the application needs to be packaged with a special VFS directory in its installation directory which defines what folders the VFS will redirect. 

In theory the behaviour of the VFS could have been implemented entirely in user mode, although that might have been unreliable. Instead it’s implemented using a kernel mode filter driver (specifically in wcnfs.sys) which will rewrite certain file paths and issue a reparse to handle the virtualized files.

The reason this behaviour is a problem is no checks seem to be done on whether the file request is coming from kernel mode or user mode. It’s entirely based on whether file request is operating in the process context of the desktop bridge application. This can lead to issues if kernel code running inside the desktop bridge process context tries to access system files assuming that a non-administrator could not replace them. However when running in a desktop bridge application that cannot be guaranteed. It’s possible to redirect files even if the kernel code is careful to avoid using the per-user Dos Devices directory (\?? Or \DosDevices) and instead uses a direct device path, or more commonly use of the \SystemRoot symbolic link.

An example of kernel code which does this is the NtGetNlsSectionPtr system call. This call will try and open a file of the pattern \SystemRoot\c_%d.nls and map it read only before returning the mapping to the caller. I blogged about abusing this system call (<a href="https://googleprojectzero.blogspot.com/2017/08/windows-exploitation-tricks-arbitrary.html" title="" class="" rel="nofollow">https://googleprojectzero.blogspot.com/2017/08/windows-exploitation-tricks-arbitrary.html</a>) to get an arbitrary file read, even to locked files such as the SAM hive. However in order to exploit the system call you need to force the file c_%d.nls to be redirected to another file using a mount point or another type of symbolic link. This shouldn’t be something that a typical appx file could install nor would it presumably pass through the MS store review so instead we can exploit an implementation flaw in the reparse operation.

When the filter driver detects the application is trying to access a system resource the driver looks up the VFS path in a set of mapping tables which are configured by the daxexec library during the creation of the Desktop Bridge application in the AppInfo service. If a mapping path is discovered then the code will call IoReplaceFileObjectName with the destination path and return STATUS_REPARSE. As a full path needs to be specified for the object manager to restart the parsing operation the driver ensures the path has the volume name prepended (WcnPrependVolumeDeviceName) however what it adds uses the per-user dos device prefix. So a request for an path such as \SystemRoot\c_1337.nls ends up reparsing to \??\c:\Program Files\AppName\VFS\SystemX64\c_1337.nls. As we’re not in a sandbox and the file open request is running inside the current process context we can replace the C: drive either at the process or per-user level and get this reparse operation to redirect anywhere we like. 

By exploiting this behavior we can cause NtGetNlsSectionPtr to map read-only any file we like on the system, even bypassing file locking leading to clear EoP. There is one final hurdle to overcome, we don’t really want to have to submit an application to the MS app store to exploit this behavior, so how can we exploit it? All we need is to install an existing application (which a normal user can do) from the store which uses the VFS feature (if the VFS directory doesn’t exist then this isn’t enabled at all I don’t believe) then either inject into that process or just create a new process which inherits the desktop bridge container for that process (which can be done with the appropriate flags to CreateProcess). It turns out that in most cases you don’t even need to install a new application as the Get Office/My Office Adware installed by default on all new installs of Windows 10 now uses Desktop Bridge and VFS for the system folder.

Putting it all together this is how we can exploit this behavior to read arbitrary files:

1. Start a desktop bridge application which uses the VFS feature for the native system folder (so SystemX64 on 64 bit and SystemX86 on 32 bit). 
2. Start a new child process from the desktop bridge application specifying the override flag to the PROC_THREAD_ATTRIBUTE_DESKTOP_APP_POLICY attribute to create the process in the same desktop bridge container.
3. Create a fake VFS path drive which points to an arbitrary location by redirecting the root drive.
4. Call NtGetNlsSectionPtr to open the file and map it as read-only.

Note that the reading of files is just an exploitation of the underlying issue. There are a number of places in the kernel as well as in drivers which could be exploited using the same behavior, which might for example load arbitrary drivers off disk or load configuration data from an untrusted location even though the driver was careful about avoiding trivial attacks.

Proof of Concept:

I’ve provided a PoC as a C# project. In order for the exploit to work you need a copy of the Get Office/My Office application installed which matches the native bitness of the platform. This is obviously only an issue on 64 bit windows. I’ve seen both x86 and x64 versions of the application, however I think Enterprise is the only platform which gets the x64 version. If you get an error about Office Hub being a Wow64 process this is the cause. It might be possible to package up the x64 version from a different system and install it manually but I didn’t check that. Therefore for ease just run this on a 32 bit version of Windows.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Start the Get Office/My Office application
3) Start the poc. It should print that it successfully opened the SAM hive.

Expected Result:
It’s not possible to redirect kernel file requests to arbitrary files.

Observed Result:
It’s possible to redirect the request for the code page file the SAM registry hive which should not be accessible by a normal user.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.




Found by: forshaw

### CVE-2018-0880


Windows: Windows: Desktop Bridge Virtual Registry Arbitrary File Read/Write EoP
Platform: Windows 1709 (not tested earlier version)
Class: Elevation of Privilege

Summary: The handling of the virtual registry for desktop bridge applications can allow an application to create arbitrary files as system resulting in EoP.

Description:
The desktop bridge functionality introduced in Anniversary edition allows an application to set up a virtual registry to add changes to system hives and user hives without actually modifying the real hives. The configuration of these registry hives is by passing a data structure to the virtual registry driver in the kernel. Loading new hives requires SeRestorePrivilege so the loading of the hives is done in the AppInfo service as part of the Desktop AppX initialization process using the container/silo APIs. In order to have this privilege the registry loader must be called by an administrator, in this case the SYSTEM user.

This is a security issue because the registry hive files are stored inside the user’s profile under %LOCALAPPDATA%\Packages\PackageName\SystemAppData\Helium. It’s possible to replace the directories with mount points/symlinks to redirect file access. This can be used to load arbitrary registry hives including ones not accessible normally by a user, but the most serious consequence of this is if a registry hive is opened for write access the kernel will try and create a couple of log files in the same directory if they don’t already exist. If you redirect the creation of these files to another location using symlinks you can create arbitrary files on disk. 

This also applies to the main hive file as well, but the advantage of the log files is the kernel will create them with the same security descriptor as the main hive which means they can be accessed by the normal user afterwards. The known writable hive files which can be abused in this way are:

User.dat
UserClasses.data
Cache\XXXX_COM15.dat

Again we can use the Get/My Office application installed by default. Note that you only need a valid Desktop Bridge application, you don’t need one which actually has a registry.dat file installed as the user hives and com15 hives seem to be created regardless.

This issue is due to a fundamental problem in the implementation of the hive loading APIs, it's dangerous to load hives from a user accessible location as it must be done as an admin to have the required privilege. I've reported similar issues before. Considering the virtual registry driver is the one loading the hive perhaps you could pass a token handle to the driver which the kernel will impersonate during loading, after it's verified the SeRestorePrivilege from the current caller.

NOTE: Please don’t ignore the fact that this can also be used to load arbitrary registry hives that the user normally can’t access, as long the hive is accessible by SYSTEM. I’ve only sent the one issue but you should also ensure that any fix also takes into account the read issue as well.

Proof of Concept:

I’ve provided a PoC as a PowerShell script. You need to install my NtObjectManager module from PSGallery first (using Install-Module NtObjectManager). In order for the exploit to work you need a copy of the Get Office/My Office application installed (I tested with version 17.8830.7600.0).

The exploit works as follows:
* The Helium\Cache folder is renamed to Cache-X.
* The Cache folder is recreated as a mount point which redirects to the object manager directory \RPC Control
* Symbolic links are dropped for the registry hive files. The LOG files are redirected to an arbitrary name in the windows folder.

1) Install the NtObjectManager module and set execution policy for PS to Bypass.
2) Start the Get/My Office application once to ensure the user directories and registry hives have been created.
3) Start the poc in powershell, it should print it’s waiting for you to start the Office Hub application.
4) Start the Get/My Office application, it should be immediately killed.

Note that the PoC will leave the user profile for the Office Hub application broken, you should delete the fake Cache folder and rename the Cache-X folder to try the exploit again.

Expected Result:
The application creation fails or at least the symbolic links aren’t followed.

Observed Result:
Two new files are created in the c:\windows folder with potentially arbitrary names which are also writable by a normal user.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.





Found by: forshaw

### CVE-2018-0882


Windows: Desktop Bridge Virtual Registry NtLoadKey Arbitrary File Read/Write EoP
Platform: Windows 1703 (version 1709 seems to have fixed this bug)
Class: Elevation of Privilege

Summary: The handling of the virtual registry NtLoadKey callback reloads registry hives insecurely leading to arbitrary file creation resulting in EoP.

Description:

NOTE: This bug seems to have been fixed in 1709, but the fix hasn’t been backported to 1703 (I’ve not checked 1607). I don’t know if the fix was intentional or not, however as (according to <a href="https://support.microsoft.com/en-gb/help/13853/windows-lifecycle-fact-sheet" title="" class="" rel="nofollow">https://support.microsoft.com/en-gb/help/13853/windows-lifecycle-fact-sheet</a>) 1703 should be supported until at least September 2018 this should be something you’d consider fixing.

The desktop bridge functionality introduced in Anniversary edition allows an application to set up a virtual registry to add changes to system hives and user hives without actually modifying the real hives. This is implemented through the normal registry callback functionality. One of the callbacks implemented is to handle the NtLoadKey system call (VrpPreLoadKey). On 1703 it doesn’t check for the Application Key flag, but then recalls ZwLoadKey with the arguments passed by the user mode caller. This effectively allows you to circumvent the requirement for SeRestorePrivilege as will also create a new hive file with kernel privileges in the context of the current user. This is a trivial EoP by dropping a arbitrary file to disk then getting system privileges.

Proof of Concept:

I’ve provided a PoC as a C# project. In order for the exploit to work you need a copy of the Get Office/My Office application installed (I tested with version 17.8830.7600.0). It could be any desktop bridge application however as you just need to run a program inside the container. Again I’ll note that this will only work on 1703 as the code seems to have been fixed in 1709. The registry hives files it creates will be locked (we can’t easily unload the hive) until reboot although it’s probably possible to trick the system into failing the load while still creating some files.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Start the Get Office/My Office application
3) Start the poc. It should print that it successfully created the registry files.

Expected Result:
Loading the registry key should fail.

Observed Result:
The registry key is loaded and the file test.hiv has been created in the windows folder with full access for the current user.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.




Found by: forshaw

### CVE-2018-0966


Windows: CiSetFileCache TOCTOU CVE-2017-11830 Incomplete Fix
Platform: Windows 10 1709 (including Win10S)
Class: Security Feature Bypass

Summary:
The fix for CVE-2017-11830 is insufficient to prevent a normal user application adding a cached signing level to an unsigned file by exploiting a TOCTOU in CI leading to circumventing Device Guard policies.

Description:
The previous issue I reported was due to not checking for write access on the target file handle when setting the cache. This allows a user application to abuse a TOCTOU and rewrite the file after the hash has been generated for the file. The only changed code seems to be below:

FILE_OBJECT target_file;
ObReferenceObjectByHandle(FileHandle, 0, *IoFileObjectType, &target_file); 
if (target_file->SharedWrite) {
   return STATUS_SHARING_VIOLATION;
}

if (target_file->WriteAccess) {  ← Additional check for the file being opened for write.
      if ((PsGetProcessProtection(PsGetCurrentProcess()) & 7) != ProtectedProcessLight)
        return STATUS_SHARING_VIOLATION;
}

The fix was to add a check that the target file passed isn’t writable. This combined with the check for FILE_SHARE_WRITE should mean the user can’t hold on to a writable file handle. However, when the file handle is converted to a file object with ObReferenceObjectByHandle the desired access is 0, which means we can pass a handle with any granted access including SYNCHRONIZE or READ_CONTROL, which do not respect file sharing. So we can still exploit this issue by doing the following:

1. Open the file for write access.
2. Reopen another handle to the file for SYNCHRONIZE access. This works as this access right can be used regardless of the sharing mode.
3. Set cached signing level through the handle opened in 2.
4. Wait for oplock, rewrite file using handle opened in 1. Release oplock.

Proof of Concept:

I’ve provided a PoC as a C# project. It will allow you to “cache sign” an arbitrary executable. If you want to test this on a locked down system such as Win10S you’ll need to sign the PoC (and the NtApitDotNet.dll assembly) so it’ll run. Or use it via one of my .NET based DG bypasses, in that case you can call the PoC_CacheSignature.Exploit.Run method directly. It copies notepad to a file, attempts to verify it but uses an oplock to rewrite the contents of the file with the untrusted file before it can set the kernel EA.

1) Compile the C# project. It will need to grab the NtApiDotNet v1.1.7 package from NuGet to work.
2) Execute the PoC passing the path to an unsigned file and to the output  “cache signed” file, e.g. poc unsigned.exe output.exe
3) You should see it print the signing level, if successful.
4) You should not be able to execute the unsigned file, bypassing the security policy enforcement.

NOTE: If it prints an exception then the exploit failed. The opened catalog files seemed to be cached for some unknown period of time after use so if the catalog file I’m using for a timing signal is already open then the oplock is never broken. Just rerun the poc which will pick a different catalog file to use. Also the output file must be on to a NTFS volume with the USN Change Journal enabled as that’s relied upon by the signature level cache code. Best to do it to the boot drive as that ensures everything should work correctly.

Expected Result:
Access denied or at least an error setting the cached signing level.

Observed Result:
The signing level cache is applied to the file with no further verification. You can now execute the file as if it was signed.

This bug is subject to a 90 day disclosure deadline. If 90 days elapse without a broadly available patch, then the bug report will automatically become visible to the public.




Found by: forshaw

### Windows: WLDP CLSID policy .NET COM Instantiation UMCI Bypass 




Windows: WLDP CLSID policy .NET COM Instantiation UMCI Bypass 
Platform: Windows 10S 1709 (or any Windows 10 with UMCI)
Class: Security Feature Bypass

Summary:
The enlightened Windows Lockdown Policy check for COM Class instantiation can be bypassed by using a bug in .NET leading to arbitrary code execution on a system with UMCI enabled (e.g. Device Guard)

Description:

The WLDP COM Class lockdown policy contains a hardcoded list of 8 to 50 COM objects which enlightened scripting engines can instantiate. Excluding issues related to the looking up of the correct CLSID (such as previously reported abuse of TreatAs case 40189). This shouldn’t be a major issue even if you can write to the registry to register an existing DLL under one of the allowed COM CLSIDs as a well behaved COM implementation should compare the CLSID passed to DllGetObject against its internal list of known objects.

Turns out .NET is not one of these well behaved COM implementations. When a .NET COM object is instantiated the CLSID passed to mscoree’s DllGetClassObject is only used to look up the registration information in HKCR. At this point, at least based on testing, the CLSID is thrown away and the .NET object created. This has a direct impact on the class policy as it allows an attacker to add registry keys (including to HKCU) that would load an arbitrary COM visible class under one of the allowed CLSIDs. As .NET then doesn’t care about whether the .NET Type has that specific GUID you can use this to bootstrap arbitrary code execution by abusing something like DotNetToJScript (<a href="https://github.com/tyranid/DotNetToJScript" title="" class="" rel="nofollow">https://github.com/tyranid/DotNetToJScript</a>). 

Proof of Concept:

I’ve provided a PoC as two files, an INF file to set-up the registry and a SCT file. On Windows 10S 1709 my old trick of using REGINI is now blocked, so instead we’ll use an INF file to install the necessary registry keys. The SCT file is just an example build from my DotNetToJScript tool which will load an untrusted .NET assembly into memory which displays a simple message box. Obviously it could do a lot more than that.

1) Unpack the PoC and ensure the files do NOT have MOTW.
2) From the explorer Run dialog execute “RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 128 path-to-inf\keys.inf”
3) Execute the SCT file from the Run dialog using “regsvr32 /u /i:path\to\poc.sct scrobj.dll”

Expected Result:
The class creation should fail.

Observed Result:
The class creation succeeded and arbitrary .NET code is run showing a message box.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse
or a patch has been made broadly available, the bug report will become
visible to the public.




Found by: forshaw

### CVE-2018-8134


Windows: Token Trust SID Access Check Bypass EOP
Platform: Windows 10 1709 (also tested current build of RS4)
Class: Elevation of Privilege

Summary: A token’s trust SID isn’t reset when setting a token after process creation allowing a user process to bypass access checks for trust labels.

Description:

When a protected process is created it sets the protection inside the EPROCESS structure but also adds a special trust SID to the primary token as part of SeSubProcessToken. Where the process protection is used for things such as what access rights to other processes the trust SID is used for direct access checks where a security descriptor has a process trust label. A good example is the \KnownDlls object directory which is labeled as PPL-WinTcb to prevent tampering from anything not at that protection level.

This trust SID isn’t cleared during duplication so it’s possible for a non-protected process to open the token of a protected process and duplicate it with the trust SID intact. However using that token should clear the SID, or at least cap it to the maximum process protection level. However there’s a missing edge case, when setting a primary token through NtSetInformationProcess (specifically in PspAssignPrimaryToken). Therefore we can exploit this with the following from a normal non-admin process:

1) Create a protected process, werfaultsecure.exe is a good candidate as it’ll run PP-WinTcb. It doesn’t have to do anything special, just be created.
2) Open the process token (we get PROCESS_QUERY_LIMITED_INFORMATION) and duplicate it to a new primary token.
3) Create a new suspended process which will run the exploit code with the original token. 
4) Set the protected process token using NtSetInformationProcess
5) Resume exploit process and do something which needs to pass the trust label check.

NOTE: There is also a related issue during impersonation and the call to SeTokenCanImpersonate. Normally the current process trust SID is checked against the impersonation token trust SID and if the process token’s is lower a flag is returned to the caller which resets the new token’s trust SID to the process one. This check occurs before the check for SeImpersonatePrivilege but _after_ the check for an anonymous token authentication ID. Therefore if you’re an admin you could craft a token with the anonymous token authentication ID (but with actual groups) and do a similar trick as with the process token to prevent the reset of the trust SID during impersonation. However I couldn’t find an obvious use for this as the trust label seems to be based on the minimum between the impersonation and process token’s trust SIDs and when impersonating over a boundary such as in RPC it looks like it gets reset to the process’ protection level. But might be worth cleaning this up as well if you’re there.

Proof of Concept:

I’ve provided a PoC as a C# project. It does the previous described trick to run a process which can then set the trust label on a new event object it creates (\BaseNamedObject\PPDEMO). If you run the poc with a command line parameter it will try and do the event creation but should print access denied.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Run the poc with no parameters as a normal user. It will capture the token and respawn itself to create the event.

Expected Result:
Setting the trust label returns access denied.

Observed Result:
The trust label is successfully set.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.




Found by: forshaw

### CVE-2018-0982


Windows: Child Process Restriction Mitigation Bypass
Platform: Windows 10 1709 (not tested other versions)
Class: Security Feature Bypass

Summary:

It’s possible to bypass the child process restriction mitigation policy by impersonating the anonymous token leading to a security feature bypass.

Description:

Windows 10 has a mitigation policy to restrict a process creating new child processes. I believe the main rationale is to prevent escaping some of the other mitigations which are not inherited across to new child processes as well as bugs which can only be exploiting from a fresh process. The policy is enforced as a flag in the token rather than on the process which allows the restriction to be passed across process boundaries during impersonation, which would also kill abusing WMI Win32_Process and similar.

During process creation the token flag is checked in SeSubProcessToken which creates the new primary token for the new process. It’s possible to also specify a flag for overriding the behavior, the code looks something like the following:

if (ChildProcessOptions & PROCESS_CREATION_CHILD_PROCESS_OVERRIDE)
{
    PTOKEN CurrentToken = PsReferenceEffectiveToken(
            KeGetCurrentThread(),
            &Type,
            &CopyOnOpen,
            &ImpersonationLevel);
    if ( Type == TokenImpersonation && ImpersonationLevel < SecurityImpersonation 
      || (SeTokenIsNoChildProcessRestrictionEnforced(CurrentToken) != 0 && Type != TokenPrimary))
    {
      return STATUS_CHILD_PROCESS_BLOCKED;
    }
}

This checks if the PROCESS_CREATION_CHILD_PROCESS_OVERRIDE is set then either the primary or impersonation token do not have the restrict child process flag set. If the token does have the flag then STATUS_CHILD_PROCESS_BLOCKED is returned and process creation fails. The problem with this code is it entirely relies on a process not being able to get an impersonation token without the flag. For a normal user process this would be trivial (of course it’s trivial to bypass this restriction from a normal process anyway) but from an AppContainer it should be much more difficult.

There is an easy token we can impersonate which doesn’t have the flag set, the Anonymous token. The problem with this is if we impersonate over the entire process creation then it will fail because the kernel will not be able to open the target executable. Fortunately the check for child process creation is after opening the file so we can abuse oplocks and from a separate thread assign the impersonation token while the thread is still running kernel code. So the following steps can be used to create an arbitrary child process:

1. Place an oplock on the image file for the process we want to create and wait for completion.
2. In a separate thread create a new process with the desired image file.
3. Once oplock has completed impersonate the anonymous token on the thread calling create process. Release oplock.
4. Original thread should continue process creation and check the anonymous token for the restricted flag bypassing the mitigation.

Note that you could probably also abuse the conhost creation inside ConDrv as that runs with kernel permissions so won’t actually care about the anonymous token but it would be nicer to demonstrate this bypass with an arbitrary process. 

From a fixing perspective I’m not entirely clear what the purpose of checking the impersonation token is. I’m guessing it’s supposed to allow a secondary process without restriction to use a process which has the restriction as a parent process using a process attribute. In that case perhaps you need a check that the parent process attribute is set and we’re not being called from the same process or something similar so that only that use case can pass the override flag.

Proof of Concept:

I’ve provided a PoC as a C# project. It will first respawn itself into an AppContainer with the child process restriction mitigation enabled. The use of a AppContainer shows that this would be normally much more difficult to circumvent as you can’t just open other processes. It will then use the outlined attack to bypass the restriction and respawn itself a second time. If successful there should be three copies of the poc running, two with child process creation restrictions inside an AppContainer.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Apply the ALL_APPLICATIONS_PACKAGES Read/Execute ACE to the POC’s directory otherwise respawning as an AC will not work.
2) Execute the PoC

Expected Result:
The second process should fail to create a new process.

Observed Result:
The second process creates a new process and the third process in the chain shows a Hello message box.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.





Found by: forshaw

### CVE-2018-8208


Windows: Desktop Bridge Activation Arbitrary Directory Creation EoP
Platform: Windows 10 1703, 1709 (not tested RS4)
Class: Elevation of Privilege

Summary: The activator for Desktop Bridge applications calls CreateAppContainerToken while running as a privileged account leading to creation of arbitrary object directories leading to EoP.

Description:
As much of the activation of Desktop Bridge applications require TCB privilege (such as creating the container) it’s delegated to the AppInfo service which runs as Local System. During post activation, either through RAiLaunchProcessWithIdentity or RAiFinishPackageActivation the API PostCreateProcessDesktopAppXActivation is called in daxexec which sets up various things. One of those things is registering the process with the Process State Manager service and to do that it passes an AppContainer token for the AppX package. 

To create the token the service will call the API CreateAppContainerToken, however it doesn’t impersonate the user while doing this which results in the service setting up the AppContainer object directories as the process user. By placing symbolic links into these locations arbitrary object directories can be created, as long as the parent directory can be written by Local System. The created directories are also given an explicit DACL which grants the user access so that they can also be written to by the original user once created. 

On Windows 8.1 this would be trivial to exploit as NtCreateLowBoxToken didn’t care what handles you passed it for capture, however since CVE-2015-2554 (which I reported) the system call checks that the directories are under the AppContainerNamedObjects directory for the user. They’re still created but once NtCreateLowBoxToken is called they’ll be closed again. However due to the way kernel objects persist it just becomes a race condition, as long as you open the directory you want before all handles are closed then you can keep it alive to do what you need to do with it. In practice it seems to be possible to capture the directory reliably but perhaps only on multi core systems.

IMO this might be best to fix in CreateAppContainerToken, perhaps by impersonating the base token which is being used to create the lowbox one. I’ve tried to track down cases before where this function is called inappropriately and it wouldn’t surprise me if there’s more bad callers for this function as impersonation can be tricky to get right, especially when hidden behind RAI C++ classes. 

As an aside it’s also worth noting that this type of bug is of more general application to the session 0 AppContainerNamedObjects directory. That directory granted access to the Everyone group to write to it as shown below.


PS C:\> $d = Get-NtDirectory \Sessions\0\AppContainerNamedObjects
PS C:\> $d.SecurityDescriptor.Dacl

Type       User                           Flags                Mask
----       ----                           -----                ----
Allowed    Everyone                       None                 0002000F
Allowed    NT AUTHORITY\SYSTEM            None                 000F000F
Allowed    NT AUTHORITY\RESTRICTED        None                 00000002
Allowed    APPLICATION PACKAGE AUTHORI... None                 00000003
Allowed    APPLICATION PACKAGE AUTHORI... None                 00000003
Allowed    NT AUTHORITY\SYSTEM            ObjectInherit, Co... 10000000

Previously nothing used it in Session 0 but in a recent update the UMFD process spawns in Session 0 as an AC and so the directories would be created by a system process which could be redirected. I’m not sure that’s very useful but it’s something which you might also want to fix.

Proof of Concept:

I’ve provided a PoC as a C# project. As it’s a race condition it should be run on a multi-core machine to give the threads a chance to capture the directory object. It might work on a single core as well but I’ve not tested it. If it fails to get the directory try it again as it’s possible that the race wasn’t successfully won. It uses the My Office application as with previous exploits, if it’s not installed then the PoC will fail. However it doesn’t need a specific Desktop Bridge application just any installed will do though you’d have to modify the package information in the PoC to do so. The PoC will try and create the folder \Blah in the object manager namespace.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Run the PoC, if the PoC says that OfficeHub is already running ensure it’s closed.
3) If a dialog appears saying the application has failed to start click OK.
4) The poc should print whether it captured the directory and if so what access was granted.

Expected Result:
Create of the application should fail and the directories are not created.

Observed Result:
The directories are created, the application will still fail.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.



Found by: forshaw

### CVE-2018-8214


Windows: Windows: Desktop Bridge Virtual Registry CVE-2018-0880 Incomplete Fix EoP
Platform: Windows 1709 (not tested earlier version)
Class: Elevation of Privilege

Summary: The handling of the virtual registry for desktop bridge applications can allow an application to create arbitrary files as system resulting in EoP. This is because the fix for CVE-2018-0880 (MSRC case 42755) did not cover all similar cases which were reported at the same time in the issue.

Description:

Looking at the fix for CVE-2018-0880 the Cache directory and sub files are now secured so only admins and system can access them. This breaks my original PoC but it doesn’t fix the issue. In my original report I also noted that User.dat and UserClasses.dat could also be abused in the same way and those files exist in the Helium directory above the Cache. Therefore the exact same attack can be employed on the Helium directory instead of the Cache directory.

To be honest I’m not even convinced that locking down the security on the Cache directory is a robust fix. As we have FILE_DELETE_CHILD access on the Helium directory we could always rename the Cache folder and the activator will recreate it for us. With a bit of effort we could mount the original attack through things like holding a reference to one of the files with WRITE_DAC permissions and race the security descriptor checks in DAXEXEC!OfflineRegistry::EnsureCacheIsSafe. It’d be slightly more work but not unduly so. 

IMO the only real way to fix this issue would be completely remove the opportunity to replace the registry cache files from a normal user, perhaps by placing them in a secondary location on the system such as under a secured directory in c:\ProgramData. 

I also haven’t bothered to check if you’ve fixed the read issue that I also reported as part of case 42755. I’ve no reason to believe you have based on what I can see in the code.

Proof of Concept:

I’ve provided a PoC as a C# project. In order for the exploit to work you need a copy of the Get Office/My Office application installed (I tested with version 17.8830.7600.0). It could be any desktop bridge application however as you just need to run a program inside the container although for that to work some strings in the poc would need to be changed.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Start the poc. It should print that it successfully created the badgers.dll file in system32.

The exploit works as follows:
* The Helium folder is renamed to Helium-X.
* The Helium folder is recreated as a mount point which redirects to the object manager directory \RPC Control
* Symbolic links are dropped for the registry hive files. The LOG files are redirected to an arbitrary name in the windows folder.

Note that the PoC will leave the user profile for the Office Hub application broken, you should delete the fake Helium folder and rename the Helium-X folder to try the exploit again.

Expected Result:
The application creation fails or at least the symbolic links aren’t followed.

Observed Result:
The file badgers.dll is created in the system32 folder which is writable by a normal user.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available, the bug report will become visible to the public.



Found by: forshaw

### CVE-2018-8449


Windows: CiSetFileCache TOCTOU CVE-2017-11830 Variant WDAC Security Feature Bypass
Platform: Windows 10 1803, 1709 (should include S-Mode but not tested)
Class: Security Feature Bypass

Summary:
While the TOCTOU attack against cache signing has been mitigated through NtSetCachedSigningLevel it’s possible to reach the same code via NtCreateSection leading to circumventing WDAC policies and CIG/PPL. 

Description:
I'm reporting this as you've fixed the previous issues (cases 43036 and 40101) so I'm making an assumption you'd also fix this one. The previous issues allowed a unprivileged caller to exploit a race condition in the CiSetFileCache kernel function by calling NtSetCachedSigningLevel. These issues should now be fixed. During my research into PPL/PP bypasses I noticed that the cache will also be written during the initial creation of an image section, when the process is running with an increased section signing level. This is presumably to allow the kernel to cache the signature automatically. This is an issue because it’s possible to create an image section with a writable (and executable) handle to the file and no part of CI then checks whether the caller has write access. It’s possible to have an elevated section signing level by enabling the ProcessSignaturePolicy process mitigation policy, it’s not required to be in a PPL. In fact, while I’ve not tested it, it’s possible that just running inside a process on Windows 10 S-Mode would be sufficient as the section signing level should be elevated for WDAC. 

So to exploit this we can do the following:

1. Elevated the section signing level of the current process using SetProcessMitigationPolicy or just running in a WDAC/CIG process.
2. Copy a valid signed file to a known name then open a writable and executable handle to that file.
3. Set an oplock on a known catalog file which will be checked
4. Call NtCreateSection with the handle requesting SEC_IMAGE.
5. Wait for oplock to fire, rewrite the file with an untrusted binary, then release oplock.
6. Close section and file handles. The cache should have been applied to the untrusted file.

Perhaps CI should check whether the file handle has been opened for write access and not write out the cache in those cases as realistically creating an image section from a writable handle should be an unusual operation. The normal loader process opens the handle only for read/execute.

Proof of Concept:

I’ve provided a PoC as a C# project. It will allow you to “cache sign” an arbitrary executable. To test on S-Mode you’ll need to sign the PoC (and the NtApitDotNet.dll assembly) so it’ll run. It copies notepad to a file, attempts to verify it but uses an oplock to rewrite the contents of the file with the untrusted file before it can set the kernel EA.

1) Compile the C# project. It will need to grab the NtApiDotNet v1.1.15 package from NuGet to work.
2) Execute the PoC passing the path to an unsigned file and to the output  “cache signed” file, e.g. poc unsigned.exe output.exe. Make sure the output file is on a volume which supports cached signing level such as the main boot volume.
3) You should see it print the signing level, if successful.
4) You should now be able to execute the unsigned file, bypassing the security policy enforcement.

NOTE: If it prints an exception then the exploit failed. The opened catalog files seemed to be cached for some unknown period of time after use so if the catalog file I’m using for a timing signal is already open then the oplock is never broken. Just rerun the poc which will pick a different catalog file to use. Also the output file must be on to a NTFS volume with the USN Change Journal enabled as that’s relied upon by the signature level cache code. Best to do it to the boot drive as that ensures everything should work correctly.

Expected Result:
Access denied or at least an error setting the cached signing level.

Observed Result:
The signing level cache is applied to the file with no further verification. You can now execute the file as if it was signed.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse
or a patch has been made broadly available (whichever is earlier), the bug
report will become visible to the public.




Found by: forshaw

### CVE-2018-8410


Windows: Double Dereference in NtEnumerateKey Elevation of Privilege
Platform: Windows 10 1803 (not vulnerable in earlier versions)
Class: Elevation of Privilege

Summary: A number of registry system calls do not correctly handle pre-defined keys resulting in a double dereference which can lead to EoP.

Description:

The registry contains a couple of predefined keys, to generate performance information. These actually exist in the the machine hive under \Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib. When these keys are opened the kernel returns a status code of STATUS_PREDEFINED_KEY, but it also returns a handle to the key. 

The kernel doesn’t allow these keys to be used for many operations such as enumeration of subkeys and values, so these system calls check before the key is used and returns STATUS_INVALID_HANDLE. The code for this in NtEnumerateKey looks like the following:

status = ObReferenceObjectByHandle(Handle, KEY_ENUMERATE, CmKeyObjectType, &Object);
if ( status >= 0 && Object->Type != 'ky02' )  {
      status = STATUS_INVALID_HANDLE;
      ObfDereferenceObject(Object); <-- Dereference object,
 }
 if (status < 0) {
   goto EXIT_LABEL;
 }

This code in itself is fine, but in 1803 at the exit label we find the following additional code:

if (Object)
    ObfDereferenceObject(Object);

This results in the object being dereferenced twice. Due the way the object reference counting works this will not be noticed until the key handle is closed, which results in a REFERENCE_BY_POINTER bugcheck being generated. This might only be a local DoS if the issue was caught earlier, but because the caller can do other things with the corrupted object we can potentially turn this into a UaF and from there elevate privileges. For example the provided PoC passes the handle to NtDuplicateObject which results in the kernel modifying a free pool allocation.

I’d recommend ensuring you check all similar functions such as NtEnumerateValueKey as there seems to be a common issue, perhaps it’s a macro or template which is generating the bad code.

The following is an example dump from a crash, at the end the !pool command is used on the object address to demonstrate the memory allocation was freed before being modified.

Use !analyze -v to get detailed debugging information.

BugCheck 18, {0, ffff8e0db3a0f7a0, 2, ffffffffffffffff}

Probably caused by : ntkrnlmp.exe ( nt!ObfDereferenceObjectWithTag+155dd9 )

Followup:     MachineOwner
---------

0: kd> !analyze -v
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

REFERENCE_BY_POINTER (18)
Arguments:
Arg1: 0000000000000000, Object type of the object whose reference count is being lowered
Arg2: ffff8e0db3a0f7a0, Object whose reference count is being lowered
Arg3: 0000000000000002, Reserved
Arg4: ffffffffffffffff, Reserved
	The reference count of an object is illegal for the current state of the object.
	Each time a driver uses a pointer to an object the driver calls a kernel routine
	to increment the reference count of the object. When the driver is done with the
	pointer the driver calls another kernel routine to decrement the reference count.
	Drivers must match calls to the increment and decrement routines. This bugcheck
	can occur because an object's reference count goes to zero while there are still
	open handles to the object, in which case the fourth parameter indicates the number
	of opened handles. It may also occur when the objects reference count drops below zero
	whether or not there are open handles to the object, and in that case the fourth parameter
	contains the actual value of the pointer references count.

Debugging Details:
------------------


DUMP_CLASS: 1

DUMP_QUALIFIER: 401

BUILD_VERSION_STRING:  17134.1.amd64fre.rs4_release.180410-1804

SYSTEM_MANUFACTURER:  Microsoft Corporation

VIRTUAL_MACHINE:  HyperV

SYSTEM_PRODUCT_NAME:  Virtual Machine

SYSTEM_SKU:  None

SYSTEM_VERSION:  Hyper-V UEFI Release v3.0

BIOS_VENDOR:  Microsoft Corporation

BIOS_VERSION:  Hyper-V UEFI Release v3.0

BIOS_DATE:  03/02/2018

BASEBOARD_MANUFACTURER:  Microsoft Corporation

BASEBOARD_PRODUCT:  Virtual Machine

BASEBOARD_VERSION:  Hyper-V UEFI Release v3.0

DUMP_TYPE:  1

BUGCHECK_P1: 0

BUGCHECK_P2: ffff8e0db3a0f7a0

BUGCHECK_P3: 2

BUGCHECK_P4: ffffffffffffffff

CPU_COUNT: 2

CPU_MHZ: a98

CPU_VENDOR:  GenuineIntel

CPU_FAMILY: 6

CPU_MODEL: 8e

CPU_STEPPING: 9

CPU_MICROCODE: 6,8e,9,0 (F,M,S,R)  SIG: FFFFFFFF'00000000 (cache) FFFFFFFF'00000000 (init)

DEFAULT_BUCKET_ID:  WIN8_DRIVER_FAULT

BUGCHECK_STR:  0x18

PROCESS_NAME:  PoC_NtEnumerateKey_EoP.exe

CURRENT_IRQL:  0

ANALYSIS_SESSION_HOST:  DESKTOP-JA4I3EF

ANALYSIS_SESSION_TIME:  06-19-2018 13:36:38.0158

ANALYSIS_VERSION: 10.0.15063.468 amd64fre

LAST_CONTROL_TRANSFER:  from fffff80357473ab9 to fffff8035742c330

STACK_TEXT:  
ffffb78e`5a91f678 fffff803`57473ab9 : 00000000`00000018 00000000`00000000 ffff8e0d`b3a0f7a0 00000000`00000002 : nt!KeBugCheckEx
ffffb78e`5a91f680 fffff803`57751b9b : 00000000`00000000 00000000`00000000 00020019`00000000 ffffb78e`5a91f7c0 : nt!ObfDereferenceObjectWithTag+0x155dd9
ffffb78e`5a91f6c0 fffff803`5775157d : ffffe58b`763cf580 00000a50`00000040 ffffe58b`75c75f20 00000000`00000001 : nt!ObDuplicateObject+0x58b
ffffb78e`5a91f980 fffff803`5743c943 : ffffe58b`763c4700 00000000`008fe098 ffffb78e`5a91fa28 00000000`00000000 : nt!NtDuplicateObject+0x12d
ffffb78e`5a91fa10 00007ffa`f3cda634 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : nt!KiSystemServiceCopyEnd+0x13
00000000`008fe078 00000000`00000000 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : 0x00007ffa`f3cda634


STACK_COMMAND:  kb

THREAD_SHA1_HASH_MOD_FUNC:  <a href="https://crrev.com/4fc60443ee144421725d502d6e3b53056b889c26" title="" class="" rel="nofollow">4fc60443ee144421725d502d6e3b53056b889c26</a>

THREAD_SHA1_HASH_MOD_FUNC_OFFSET:  <a href="https://crrev.com/c219a3da6c3050112ed885b130b5ebbab9cdff96" title="" class="" rel="nofollow">c219a3da6c3050112ed885b130b5ebbab9cdff96</a>

THREAD_SHA1_HASH_MOD:  <a href="https://crrev.com/f08ac56120cad14894587db086f77ce277bfae84" title="" class="" rel="nofollow">f08ac56120cad14894587db086f77ce277bfae84</a>

FOLLOWUP_IP: 
nt!ObfDereferenceObjectWithTag+155dd9
fffff803`57473ab9 cc              int     3

FAULT_INSTR_CODE:  4e8d48cc

SYMBOL_STACK_INDEX:  1

SYMBOL_NAME:  nt!ObfDereferenceObjectWithTag+155dd9

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: nt

IMAGE_NAME:  ntkrnlmp.exe

DEBUG_FLR_IMAGE_TIMESTAMP:  5b1a4590

BUCKET_ID_FUNC_OFFSET:  155dd9

FAILURE_BUCKET_ID:  0x18_OVER_DEREFERENCE_nt!ObfDereferenceObjectWithTag

BUCKET_ID:  0x18_OVER_DEREFERENCE_nt!ObfDereferenceObjectWithTag

PRIMARY_PROBLEM_CLASS:  0x18_OVER_DEREFERENCE_nt!ObfDereferenceObjectWithTag

TARGET_TIME:  2018-06-19T20:33:20.000Z

OSBUILD:  17134

OSSERVICEPACK:  0

SERVICEPACK_NUMBER: 0

OS_REVISION: 0

SUITE_MASK:  272

PRODUCT_TYPE:  1

OSPLATFORM_TYPE:  x64

OSNAME:  Windows 10

OSEDITION:  Windows 10 WinNt TerminalServer SingleUserTS

OS_LOCALE:  

USER_LCID:  0

OSBUILD_TIMESTAMP:  2018-06-08 02:00:00

BUILDDATESTAMP_STR:  180410-1804

BUILDLAB_STR:  rs4_release

BUILDOSVER_STR:  10.0.17134.1.amd64fre.rs4_release.180410-1804

ANALYSIS_SESSION_ELAPSED_TIME:  13a4

ANALYSIS_SOURCE:  KM

FAILURE_ID_HASH_STRING:  km:0x18_over_dereference_nt!obfdereferenceobjectwithtag

FAILURE_ID_HASH:  {4139309c-4e9f-52f0-ac5e-4041e7a86a20}

Followup:     MachineOwner
---------

0: kd> !pool ffff8e0db3a0f7a0
Pool page ffff8e0db3a0f7a0 region is Paged pool
 ffff8e0db3a0f000 size:  150 previous size:    0  (Free )  FMfn
 ffff8e0db3a0f150 size:  130 previous size:  150  (Free)       Free
 ffff8e0db3a0f280 size:   40 previous size:  130  (Allocated)  MPan
 ffff8e0db3a0f2c0 size:   50 previous size:   40  (Free )  SeAt
 ffff8e0db3a0f310 size:   c0 previous size:   50  (Free )  Se  
 ffff8e0db3a0f3d0 size:   50 previous size:   c0  (Free)       Free
 ffff8e0db3a0f420 size:  220 previous size:   50  (Allocated)  FMfn
 ffff8e0db3a0f640 size:   a0 previous size:  220  (Allocated)  Sect
 ffff8e0db3a0f6e0 size:   50 previous size:   a0  (Free)       Free
*ffff8e0db3a0f730 size:  100 previous size:   50  (Free ) *Key 
		Pooltag Key  : Key objects
 ffff8e0db3a0f830 size:   10 previous size:  100  (Free)       Free
 ffff8e0db3a0f840 size:   e0 previous size:   10  (Allocated)  NtFs
 ffff8e0db3a0f920 size:   c0 previous size:   e0  (Allocated)  FIcs
 ffff8e0db3a0f9e0 size:   c0 previous size:   c0  (Free )  SeTd
 ffff8e0db3a0faa0 size:  560 previous size:   c0  (Allocated)  Ntff




Proof of Concept:

I’ve provided a PoC as a C# project. This only demonstrates the issue and proves that it would be possible to force this issue into a UaF even with the mitigations on reference counting.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Run the PoC on an machine with Windows 10 1803, I’ve only tested x64.
3) The OS should crash, inspect it in a kernel debugger or from the crash dump.

Expected Result:
The OS ignores the pre-defined key as expected.

Observed Result:
The object’s reference count is corrupted.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse
or a patch has been made broadly available (whichever is earlier), the bug
report will become visible to the public.




Found by: forshaw

### CVE-2018-8411


Windows: FSCTL_FIND_FILES_BY_SID Information Disclosure
Platform: Windows 10 (1709, 1803)
Class: Information Disclosure / Elevation of Privilege

Summary: The FSCTL_FIND_FILES_BY_SID control code doesn’t check for permissions to list a directory leading to disclosure of file names when a user is not granted FILE_LIST_DIRECTORY access.

Description: The FSCTL_FIND_FILES_BY_SID is documented to return a list of files in a directory for a specific owner. This only works when Quotas are tracked on the device which isn’t a default configuration, but could be common especially on shared terminal servers. The FSCTL code is specified for FILE_ANY_ACCESS so it’s possible to issue it for any handle on a directory regardless of the access granted, including SYNCHRONIZE. 

At least when run on an NTFS volume no check seems to occur later in the process to ensure the caller would have some sort of access to the directory which would grant them the ability to list the directory. This allows a less privileged attacker to list the file names in a directory which they’ve been granted some access, but not FILE_LIST_DIRECTORY access. A good example of such a directory on a standard installation is the Windows\Temp folder, which grants creation access to BUILTIN\Users but not the ability to list the files. This is used in part as a security measure to allow system services to create files and folders in that directory which a normal user can’t easily list. 

Proof of Concept:

I’ve provided a PoC as a C# project. It will take a path to a directory (which must be on a quota tracking volume), open that directory for Synchronize access and then list files belonging to the current owner. I have tested querying other user SIDs such as BUILTIN\Administrator so it’s not some bypass due to the current user. Note that this just simulates the behavior by only opening for Synchronize access, but I have also tested it works on directories where the user hasn’t been granted FILE_LIST_DIRECTORY.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Ensure the volume has quota tracking enabled. You can enable it from the command line with ‘fsutil quota track X:’ as an administrator.
3) Run the poc, passing the path to a directory on the volume containing files owned by the current user.

Expected Result:
An error should be returned indicating the user can’t access the directory.

Observed Result:
The files owned by the user are listed to the console.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse
or a patch has been made broadly available (whichever is earlier), the bug
report will become visible to the public.




Found by: forshaw

### CVE-2018-8550


Windows: DfMarshal Unsafe Unmarshaling Elevation of Privilege (Master)
Platform: Windows 10 1803 (not tested earlier, although code looks similar on Win8+)
Class: Elevation of Privilege

Note, this is the master issue report for the DfMarshal unmarshaler. I’m reporting multiple, non-exhaustive, issues in this marshaler in case you decide that you want to try and “fix” it rather than blocking the marshaler outright.

Summary: The unmarshaler for Storage objects is complete unsafe and yet is marked as a system trusted marshaler. There are multiple ways of abusing this to unmarshaler to get privilege escalation.

Description:

Storage objects are used by different parts of the OS and Office as a structured container format for sub-streams of data. You can create a new instance using APIs such as StgCreateDocFile. Being a COM object it can be marshaled around between processes, including special support during COM activation through CoGetInstanceFromIStorage. While all the important interfaces have proxy support the object also supports custom marshaling to improve performance when marshaling either INPROC or a LOCAL context. 

The COM class DfMarshal CLSID:0000030b-0000-0000-c000-000000000046 (in coml2.dll on Windows 10, ole32.dll downlevel) implements the custom unmarshaling for storage objects. When marshaling the implementation generates the following output:

MSHFLAGS <4 bytes>
Object Type IID <16 bytes> - Either IID_IStream or IID_IStorage.
Standard Marshaled Interface <Variable> - Used if the custom marshal fails.
SDfMarshalPacket <0x70 bytes on 64 bit, 0x44 on 32 bit> - Data for the custom marshal.

The SDfMarshalPacket has the following structure, note this comes from the Windows 8.1 private symbols for OLE32.DLL which are available on the public symbol server. On Windows 10 when the code was moved to COML2.DLL the private symbols didn’t move with it, however the code only seems to have had minor changes between 8.1 and 10.

struct SDfMarshalPacket
{
  CBasedPubDocFilePtr pdf;
  CBasedPubStreamPtr pst;
  CBasedSeekPointerPtr psp;
  CBasedMarshalListPtr pml;
  CBasedDFBasisPtr pdfb;
  CBasedGlobalContextPtr pgc;
  CBasedGlobalFileStreamPtr fsBase;
  CBasedGlobalFileStreamPtr fsDirty;
  CBasedGlobalFileStreamPtr fsOriginal;
  unsigned int ulHeapName;
  unsigned int cntxid;
  GUID cntxkey;
  CPerContext *ppc;
  HANDLE hMem;
};

The Ptr structures are native pointer sized values which are used as relative offsets into a shared memory section. The cntxid is the PID of the marshaling process, the hMem a handle to a section object which contains the shared allocation pool for use between processes. When the custom unmarshaling process starts the receiving process will try and open the process containing the shared memory handle (using cntxid and hMem) and duplicate it into the current process. Then it will map the section into memory and rebuild a local storage object based on the various relative pointers stored in the marshaled structure. Note that there is provision for performance improvements for in-process marshaling where cntxkey is a random GUID value which is known only to the process (it’s not set for cross context marshal). In that case ppc is used as a valid pointer, but ppc is always set so this leaks memory layout information to the process the object is marshaled to (not reporting this one separately). 

This will only work if the process can open the marshalling process for PROCESS_DUP_HANDLE access. This restricts this to processes at the same or higher privilege, therefore an obvious target would be unmarshaling this data from a user into a system service. Fortunately there’s some protection against that, the unmarshal occurs in CSharedMemoryBlock::InitUnMarshal and looks something like the following:

int CSharedMemoryBlock::InitUnMarshal(void *hMem, 
                                      unsigned int dwProcessId, 
                                      unsigned int culCommitSize) {
  unsigned int dwCurrentSession;
  unsigned int dwSourceSession;

  ProcessIdToSessionId(dwProcessId, &dwSourceSession);
  ProcessIdToSessionId(GetCurrentProcessId(), &dwCurrentSession);
  if (dwSourceSession != dwCurrentSession)
    return E_ACCESSDENIED;
  HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, 0, dwProcessId);
  ...
}

The code contains a check that the process containing the shared section is in the same console session as the process doing the unmarshal. If they’re not in the same session then the unmarshal process will fail. It’s unclear if this is a security check or whether it’s a reliability check, and even if it’s a security check it’s not hard to find a way around this.

One thought would be to try and use this to escape a sandbox, such as AppContainer as the sandbox process and a likely COM target would all be in the same session. While there are checks for the current process being in an AppContainer (so an AC process will never use the custom unmarshaling) there are no checks for the caller being an in AC. In fact there would be as the default HYBRID custom marshaling policy should kick in and block the custom unmarshal. However as DfMarshal is marked as a system trusted marshaler, it will still execute. It turns out that it’s difficult to trivially use this from a sandbox as later in the initialization an event object is opened by name (in CDfMutex::Init) from the current session’s BaseNamedObjects directory which an AC can’t write to. However if some other process in the same session had already shared a storage object, creating the event _and_ the AC could read the randomly assigned name it could be hijacked. 

So we’re back to either abusing something like UAC elevated processes/runas on the same desktop (doable but not a security boundary) or try and bypass the check to unmarshal from a user process into a system process. The key is the knowledge that the unmarshaler will open any process we tell it to, including other services in Session 0. The code could try and query the PID of the caller through COM (and thereby through MSRPC/ALPC) but it doesn’t. This means as long as we can get a writable section shared between our process and a process in session 0 we can tell the unmarshaler to look there for the section handle.

After some investigation I discovered that the Audio Service will create a writable section handle for you (actually via AUDIODG) and share it back to you when you create a rendering buffer (I didn’t investigation any further). This section is large enough to copy our existing shared memory from the marshal process. We can therefore create the section, copy over the existing shared memory (or fake one from scratch) then provide the PID and handle to the system service for use in unmarshaling. We don’t have to guess the handle as the handle table from NtQuerySystemInformation reports object addresses so you just match the current process’s handle and the AUDIODG handles. When the system service unmarshals this it will now pass the session check, we also have to create a duplicate event object in the global BNO but a normal user has access to that.

During the unmarshal process the implementation interacts with the shared memory as an allocation region, this is where all the issues occur. In theory if you could find a system process which actually interacts with the storage object you might find some more interesting behaviors (such as getting the system service to write to arbitrary files) but everything I’ll describe in other issues all occur during the unmarshal process and so can be used to target any system COM service using CoGetInstanceFromStorage. Basically the storage object code uses the shared memory section as if everything is running at the same level of trust and doesn’t take any real precautions against a malicious actor which has access to the same shared section or controls the existing data.

As mentioned I’m reporting 4 other issues/bug classes at the same time. This is the master issue, and potentially you can mark the others as duplicates depending on how you want to fix them. Though I’d remind you that when you marked a bug as duplicate last time it didn’t get fixed so perhaps exercise caution. The four issues I’m reporting at the same time are:

- DfMarshal Missing Bounds Checking Elevation of Privilege
- DfMarshal Shared Allocator Elevation of Privilege
- DfMarshal Arbitrary File Delete Elevation of Privilege
- DfMarshal Handle Duplication TOCTOU Elevation of Privilege

Possible fixing ideas:

DO NOT just remove the class from the trusted marshaler’s list. Some COM services such as SearchIndexer runs without the EOAC_NO_CUSTOM_MARSHAL flag set.

You could query the PID of the caller in the unmarshal process and only duplicate from that process, or processes in the same session as the caller. However bear in mind that when unmarshaling during activation (through CoGetInstanceFromStorage) the caller will actually be RPCSS so this might be bypassable. Depending on how you did it this might mean that a session hopping bug (which I’ve found before) would allow you to elevate privilege.

You could just rewrite the whole thing, it’s an incredibly bad piece of code.

You could just restrict it to a very limited set of scenarios, but again you risk bypasses due to mistakes in the checks.

Proof of Concept:

See the separate reports for PoCs for various issues I identified. The source for all PoCs is attached to this issue.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.




Found by: forshaw

### Windows: Unnamed Kernel Object Arbitrary Owner/Mandatory Label EoP 




Windows: Unnamed Kernel Object Arbitrary Owner/Mandatory Label EoP
Platform: Windows 10 1803 and 1809.
Class: Elevation of Privilege

Summary: 
When creating an unnamed kernel object it’s possible to default the security descriptor owner or mandatory label to the value from an Identification level impersonation token leading to EoP.

Description:

Normal users can’t set the owner in an object’s security descriptor to an arbitrary value, it can only be set to either the user’s SID or a group sid with the SE_GROUP_OWNER attribute set. During object creation when the default security descriptor is assigned the value of owner is set to the current value of the TokenOwner property in the effective token. The mandatory label is also checked against the effective token’s level and rejected if it’s higher.

Through testing it seems that for unnamed objects, such as anonymous sections or events, a normal user can impersonate another at identification level and the defaulting process of extracting the owner never checks that token impersonation level. This allows a user to set an almost arbitrary security descriptor owner on these objects by getting hold of an identification level token for that user (not normally hard) and creating the unnamed object while impersonating that user. For named objects the effective token is also going to be the same token used to determine whether they have access to create the named object, which means that the use of the identification level token would cause the access check to fail before setting the security descriptor.

This doesn’t have a massive security impact as I don’t believe it can be used to set the owner of a named object, nor can it be used to change the owner of an existing object. However checks for owner have been used, for example the changes in RS5 for the code reported in issue 47435 check the owner of a section which could be spoofed using this technique. At minimum it is an EoP as it shouldn’t be possible to set the owner of an object based on an identification level token. It might also indicate some deeper security issue with the object creation logic.

Proof of Concept:

I’ve provided a PoC as a C# project. It uses S4U to get an identification token for another user on the system machine and 

1) Compile the C# project. It’ll need to pull NtApiDotNet from NuGet to build.
2) Add a second user account to the machine. This is used to get a user token which is can be used for the exploit.
2) Execute the created poc passing the name of the other user you created in step 2.

Expected Result:
The creation of the second section should fail.

Observed Result:
The second section is created and the owner is set to the owner of the identification level token.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.




Found by: forshaw

### CVE-2018-6756,CVE-2018-6755,CVE-2018-6757


McAfee True Key: Multiple Issues with McAfee.TrueKey.Service Implementation
Platform: Version 5.1.173.1 on Windows 10 1809.
Class: Elevation of Privilege

Summary: 
There are multiple issues in the implementation of the McAfee.TrueKey.Service which can result in privilege escalation through executing arbitrary processes or deleting files and directories.

Description:
I discovered the main True Key service had a pre-existing vulnerability due to the Exodus Intelligence blog post (<a href="https://blog.exodusintel.com/2018/09/10/truekey-the-not-so-uncommon-story-of-a-failed-patch/" title="" class="" rel="nofollow">https://blog.exodusintel.com/2018/09/10/truekey-the-not-so-uncommon-story-of-a-failed-patch/</a>) which just discussed a DLL planting attack that had tried to be fixed once (CVE-2018-6661), but unsuccessfully. So I decided to look into service itself and especially the SecureExecute command. There are multiple issues here, which I’m not sure you’ll address. I’m only going to provide a PoC for one of them (perhaps the most serious) but you should consider fixing all of them. Starting with the most serious and working back:

1. The target file to execute in SecureExecuteCommand::Execute is checked that it has the same Authenticode certificate as the calling service binary. This should ensure that only executables signed by McAfee would validate. However you don’t actually verify the signature is valid, you only call McAfee.YAP.Security.SecurityCertificate.WinTrust::CheckCertificates which gets the certificate from the binary using X509Certificate.CreateFromSignedFile. The CreateFromSignedFile method DOES NOT verify that the signature is correct, it only extracts the X509Certificate from the security data directory. What this means is you can take the security data directory from a vaild signed file, and apply it to an arbitrary file and it’ll pass the verification checks. This allows you to execute any binary you like. There is a  VerifyEmbeddedSignature method, but you don’t actually call it. This is what I’ve sent as a POC.

2. There are multiple Time-of-Check Time-of-Use (TOCTOU) in the SecureExecuteCommand::Execute method with the filename. Let me annotate snippets of code (from ILSPY decompiler).

FileInfo fileInfo = new FileInfo(_filename); 
if (!fileInfo.Exists)  <<< File use 1
...
FileSecurity accessControl = fileInfo.GetAccessControl(); <<< File use 2
...
fileInfo.SetAccessControl(accessControl); <<< File use 3
...
if (!winTrust.CheckCertificates(_filename)) <<< File use 4
…
FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(_filename); <<< File use 5
...
Process process = Process.Start(fileInfo.ToString(), _flags); <<< File use 6
...
File.Delete(_filename); <<< File use 7

At each of these points the file is opened, some operation is performed, then the file is closed again. The simplest way this could be achieved would be using mount point symbolic links to redirect the filename to different locations. For example at point 4 the certificate of the file is checked, but at 7 the path is executed By using a mount point, which acts as a directory symlink we could do the following:

1. Create a directory mount point using “mklink /D c:\somedir c:\a”.
2. Create c:\a and copy in a McAfee signed file to c:\a\file.exe.
3. Call the SecureExecute RPC passing the path c:\somedir\file.exe.
4. At point 4 the code will open c:\somedir\file.exe to verify the certificate. This redirects to c:\a\file.exe which is a valid signed file.
5. Between 4 and 7 the mount point can be changed to point instead to c:\b. At c:\b\file.exe is an arbitrary binary. 
6. Once 7 is reached the code will execute c:\somedir\file.exe which now results in executing c:\b\file.exe which is a completely different file and not the one which was verified. 

The changing of the security descriptor at 3 is presumably supposed to prevent someone modifying the file in that time window, but of course it doesn’t take into account just changing the path underneath the code using symlinks. Also it’s possible for a process to maintain a handle with WRITE_DAC access before the code modifies the security descriptor which would allow the attacker to change it back again and rewrite the file even without abusing symlinks. This would how you’d exploit it from a sandbox environment.

In reality all of these issues (including DLL planting) could be fixed by moving the executable to run to a secure location first which only SYSTEM has access to then doing correct verification before execution.

Another issue which copying might not fix is at 7, you’re deleting an arbitrary path as the SYSTEM user. Again an attacker could replace this with a symbolic link and get you to delete any file on the disk as a privileged user. 

3. When you call McAfee.YAP.Service.Common.ClientRegister::RegisterClient you look up the PID associated with a TCP port number passed in from the client. The calling process supplies this port, when in reality you should probably extract it from the TCP server. At the moment you can pass 30000 from the client, which is what the service is listening on and it ends up verifying itself. I’ve no idea if this was the intention? The PoC abuses this to setup the RPC connection.

Also in the McAfee.YAP.Security.ClientVerifier::GetProcessPath method you using Process::MainModule::FileName to extract the calling process’ path to verify. This path is actually extracted from the memory of the target process itself (i.e. under attacker control) and so can be trivially spoofed. So don’t do that.

4. The CleanupCommand deletes values from the the shared location C:\ProgramData\McAfee\TrueKey which any user can manipulate. Again it’d be possible to abuse this command as you don’t secure the directory as shown by running icacls.

C:\ProgramData>icacls McAfee
McAfee NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
       BUILTIN\Administrators:(I)(OI)(CI)(F)
       CREATOR OWNER:(I)(OI)(CI)(IO)(F)
       BUILTIN\Users:(I)(OI)(CI)(RX)
       BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)

You could replace parts of this directory structure which symlinks and get the system service to delete arbitrary files or directories under attacker control. It might be okay to ensure these directories are created with permissions which a user can’t modify but that’s a difficult thing to get correct.

Proof of Concept:

I’ve provided a PoC as a C# project. This exploits <a href="/p/project-zero/issues/detail?id=1" title="This is a test" class="closed_ref" rel="nofollow"> issue 1 </a>. In order to compile you’ll need to take the files from the c:\program files\mcafee\truekey directory for version 5.1.173.1 and copy them into the SecureExecutePoc directory.

1) Compile the C# project. If it can’t find certain TrueKey files you haven’t copied the right ones.
2) Execute the created SecureExecutePoc.exe file.

Expected Result:
Calling SecureExecute with an untrusted binary fails.

Observed Result:
An arbitrary binary with the name tmpXXX.tmp.exe is executing as SYSTEM.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw

Windows: DSSVC CheckFilePermission Arbitrary File Delete EoP 

CVE-2018-8584


Windows: DSSVC CheckFilePermission Arbitrary File Delete EoP
Platform: Windows 10 1803 and 1809.
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

NOTE: This is one of multiple issues I’m reporting in the same service. While I’ve tried to ensure all the bugs are effectively orthogonal from each other it’s possible that fixes for one thing might affect others. I’ve also not reported every possible problem with the service as at some point I had to stop. I’ve not determined if any of these issues could be abusable from a sandbox, most of the issues almost certainly can’t be due to the requirements for arbitrary file symlinks but it’s not impossible.

Summary: 

The Data Sharing Service doesn’t has a TOCTOU in PolicyChecker::CheckFilePermission resulting in an arbitrary file deletion.

Description:

In many different places the DSSVC calls PolicyChecker::CheckFilePermission to ensure the calling user has permission to open a file with a certain set of access rights. This function has an unusual behavior, specifically it passes OPEN_ALWAYS as the disposition to CreateFile even if the code expects the file to already exist. The OPEN_ALWAYS disposition will create a file if it doesn’t exist, to handle the the code checks whether GetLastError() is 0, if it is then it assumes the file is new and so will call DeleteFile on the path.

This has a big problem, there’s a TOCTOU in that the path passed to CreateFile doesn’t need to refer to the same file that’s passed to DeleteFile. For example when this method is called in DSSCreateSharedFileTokenEx it’s using the path supplied by the user almost directly. One way of exploiting this would be to specify a path with a mount point in it, then between the call to CreateFile and DeleteFile change the mount point to point somewhere else. 

However, there’s an easier way, as CreateFile is called under impersonation and DeleteFile is not an attacker could just setup a per-user C: redirection to force the CreateFile call to open a new file in an arbitrary directory, then when DeleteFile is called it’ll be out of the impersonation so will use the system supplied C: drive.

Fixing wise you should probably reopen the original file for DELETE access then use the native APIs to delete the file by handle. Also if the file is expected to exist you perhaps should have a flag passed which indicates to use OPEN_EXISTING instead of OPEN_ALWAYS an not try and delete the file anyway.

Proof of Concept:

I’ve provided a PoC as a C# project.

1) Compile the C# project. It’ll need to pull NtApiDotNet from NuGet to build.
2) Execute the PoC passing the path to a file the user can’t delete on the command line (but can be deleted by SYSTEM).

Expected Result:
The call to DSOpenSharedFile fails and the file isn’t deleted.

Observed Result:
The file specified is deleted.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw

### CVE-2019-0543


Windows: SSPI Network Authentication Session 0 EoP
Platform: Windows 10 1803/1809 (not tested earlier versions)
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): Session boundary

Summary: Performing an NTLM authentication to the same machine results in a network token which can be used to create arbitrary processes in session 0.

Description:
Typically performing a loopback authentication would result in a short circuited authentication NTLM challenge response which will just return to the caller a copy of the token which initiated the authentication request. This token has the same properties, such as elevation status, authentication ID and session ID as the caller and so isn’t that interesting from an exploitation perspective. 

However if you initiate the authentication process by supplying a SEC_WINNT_AUTH_IDENTITY_EX structure to AcquireCredentialsHandle which has the username and domain fields set, but not the password the authentication process will instead return an authenticated network token. This is interesting because LSASS doesn’t modify the session ID of the token, which means the returned token is set to session ID 0 (network authentication doesn’t spin up a new console session). If we do the authentication to ourselves we’ll meet all the requirements to impersonate this token, it’s the same user and the same privilege level so we can then use this to spawn a new process running in session 0, where we could potentially elevate our privileges by modifying global named objects or making it easier to exploit case 47435. 

Note that not specifying any buffer to pAuthData in AcquireCredentialsHandle or passing SEC_WINNT_AUTH_IDENTITY_EX but with empty username and domain fields results in the normal loopback authentication.

While I’ve not verified this it might also work in an AppContainer if the Enterprise Authentication capability has been granted, which is allowed in some of the Edge sandbox profiles. The normal short circuit authentication would return the AC token but this approach might return the full token. With a full token you might be able to elevate privileges.

Proof of Concept:
I’ve provided a PoC as a C# project. The PoC negotiates the network access token set to Session 0 then abuses the COM activator to create a process using that access token. While I don’t control the process being created (outside of choosing a suitable COM class) it would be easy to do by modifying DOS devices to redirect the creation or just inject into the new process and execute arbitrary code.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Run the PoC, observe the text output.

Expected Result:
The negotiated token is just a reflected version of the current process token.

Observed Result:
The token is set for session 0 and a new process can be created with that session ID set.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw

### CVE-2019-0572


Windows: DSSVC DSOpenSharedFile Arbitrary File Open EoP
Platform: Windows 10 1803 and 1809.
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

NOTE: This is one of multiple issues I’m reporting in the same service. While I’ve tried to ensure all the bugs are effectively orthogonal from each other it’s possible that fixes for one thing might affect others. I’ve also not reported every possible problem with the service as at some point I had to stop. I’ve not determined if any of these issues could be abusable from a sandbox, most of the issues almost certainly can’t be due to the requirements for arbitrary file symlinks but it’s not impossible.

Summary: 

The Data Sharing Service doesn’t handle file hard links in DSOpenSharedFile resulting in a user being able to open arbitrary files for full access at system privileges. 

Description:

The Data Sharing Service allows you to setup a shared file, referenced by a GUID token by calling DSCreateSharedFileToken. The GUID token can then be passed back to DSOpenSharedFile to get a handle to the file. When the token is created the user passes a flag to indicate whether the file should be opened as Read and/or Write. This flag is then used during the call to CreateFile inside the service while running as the SYSTEM user.

In order to defend against the user replacing the file with a symlink the service checks that the opened file and the original path match by calling GetFinalPathNameByHandle. While the file will be opened as SYSTEM the user won’t get back a handle to the file to allow them to manipulate it. 

This breaks down with hard links, it’s possible for the user to setup a file to which they have full access and register the token. The file can then be deleted (as the service doesn’t maintain any lock on the file) and replace it with a hard link to a file the user can only read. This is possible as while the CreateHardlink API requires FILE_WRITE_ATTRIBUTES access the underlying system call interface does not. Now when the file is opened through DSOpenSharedFile the hardlinked file will be open for write access, the handle is DSUtils::VerifyPathFromHandle which will find the path matches the expected one and then will duplicate the handle back to the caller. The caller can now modify this file to gain full privilege escalation.

Impersonating over the call to CreateFile would fix this issue, but that might make it impossible for the service to do its job of sharing the files if the use calling DSOpenSharedFile can’t already open the file which was shared.

Proof of Concept:

I’ve provided a PoC as a C# project. It will use a hardlink to open an arbitrary file for write access (as long as it’s accessible by the SYSTEM user).

1) Compile the C# project. It’ll need to pull NtApiDotNet from NuGet to build.
2) Execute the PoC passing the path to a file the user can’t write on the command line (but can be written by SYSTEM).

Expected Result:
Opening the file fails.

Observed Result:
The file is opened and a writable handle is returned to the user. The PoC will print out the granted access and the list of hard links to the file which should include the original filename.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.




Found by: forshaw

### CVE-2019-0573


Windows: DSSVC DSOpenSharedFile Arbitrary File Delete EoP
Platform: Windows 10 1803 and 1809.
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

NOTE: This is one of multiple issues I’m reporting in the same service. While I’ve tried to ensure all the bugs are effectively orthogonal from each other it’s possible that fixes for one thing might affect others. I’ve also not reported every possible problem with the service as at some point I had to stop. I’ve not determined if any of these issues could be abusable from a sandbox, most of the issues almost certainly can’t be due to the requirements for arbitrary file symlinks but it’s not impossible.

Summary: 

The Data Sharing Service DSOpenSharedFile method takes a flag to delete a shared file on close which can be abused to delete an arbitrary file.

Description:

The DSOpenSharedFile method takes a flag parameter where the file handle can be opened overlapped or for delete on close. The delete on close flag will set the flag FILE_FLAG_DELETE_ON_CLOSE when opening the file with CreateFile. This code runs as SYSTEM so will open any file that that user has access to. However there’s a couple of issues with this:

1) The code doesn’t check that the file was shared writable, which means it’s possible to trivially specify a file to DSCreateSharedFileToken you want to delete and specify read only permissions. Then call DSOpenSharedFile with the delete on close flag, as the flag automatically adds the DELETE permission to the file open this will succeed even with the read-only mode set.
2) The DSOpenSharedFile relies on calling DSUtils::VerifyPathFromHandle prevent returning a handle which was redirected due to something like a symlink or directory junction. However by the time the code reaches the verification it’s already too late and the file will delete on close regardless of what the service now does.

While this bug relies on the same behavior as I reported for the arbitrary hardlink open issue (namely not impersonating the user when calling CreateFile) I think it should be treated separately, unless of course you decide to do the impersonation as a fix. At a minimum you should be checking that the file was shared writable in case 1, and perhaps you should open the file for DELETE in case 2, verify the path and only then delete the file by handle (using the native APIs).

Proof of Concept:

I’ve provided a PoC as a C# project. It will delete an arbitrary file that the user can read by abusing case 1 above.

1) Compile the C# project. It’ll need to pull NtApiDotNet from NuGet to build.
2) Execute the PoC passing the path to a file the user can’t delete on the command line (but can be deleted by SYSTEM).

Expected Result:
The call to DSOpenSharedFile fails and the file isn’t deleted.

Observed Result:
The file specified is deleted.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw

### CVE-2019-0571


Windows: DSSVC CanonicalAndValidateFilePath Security Feature Bypass
Platform: Windows 10 1803 and 1809.
Class: Security Feature Bypass/Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

NOTE: This is one of multiple issues I’m reporting in the same service. While I’ve tried to ensure all the bugs are effectively orthogonal from each other it’s possible that fixes for one thing might affect others. I’ve also not reported every possible problem with the service as at some point I had to stop. I’ve not determined if any of these issues could be abusable from a sandbox, most of the issues almost certainly can’t be due to the requirements for arbitrary file symlinks but it’s not impossible.

Summary: 

The Data Sharing Service’s check for the user passing UNC paths can be circumvented leading to a security feature bypass which can facilitate easier exploitation for privilege elevation.

Description:

During DSSCreateSharedFileTokenEx the path is passed to DSUtils::CanonicalAndValidateFilePath to canonicalize the path. This method also verifies that the passed path isn’t a UNC path (for reasons unknown). The UNC path check can be bypassed by using the \??\UNC\ form. When this is passed to PathAllocCanonicalize it returns it verbatim, however this path format isn’t considered a UNC path by PathIsUNCEx. However when passed to CreateFile etc it will be considered as if it was an \\?\UNC\ path format.

This could be useful for a few different attacks. For a start you could redirect the call to \\localhost\pipe\somepipe and get a named pipe handle bound to the SYSTEM user. Although I’ve not worked out a way of getting the handle back (as GetFinalPathFromHandle fails). Another attack vector is when going to an SMB share any directory junctions are resolved on the server, this would allow you to bypass any checks such as DSUtils::VerifyPathFromHandle as the returned path would be \\?\UNC\localhost\c$\blah.. Regardless of the final destination path opened. 

Proof of Concept:

I’ve provided a PoC as a C# project.

1) Compile the C# project. It’ll need to pull NtApiDotNet from NuGet to build.
2) Execute the poc, it will try and open c:\windows\notepad.exe via the C$ admin share.

Expected Result:
The path is considered invalid and DSSCreateSharedFileTokenEx fails. 


Observed Result:
The UNC path is opened.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw

### CVE-2019-0574


Windows: DSSVC MoveFileInheritSecurity Multiple Issues EoP
Platform: Windows 10 1803 and 1809.
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

NOTE: This is one of multiple issues I’m reporting in the same service. While I’ve tried to ensure all the bugs are effectively orthogonal from each other it’s possible that fixes for one thing might affect others. I’ve also not reported every possible problem with the service as at some point I had to stop. I’ve not determined if any of these issues could be abusable from a sandbox, most of the issues almost certainly can’t be due to the requirements for arbitrary file symlinks but it’s not impossible.

Summary: 

The Data Sharing Service MoveFileInheritSecurity method is broken leading to EoP.

Description:

The PolicyChecker::MoveFileInheritSecurity method is almost an exact copy of the code from the Storage Service which I exploited in MSRC cases 42121 and 42122. In fact I’d say it’s the same code copy and pasted. It has the exactly same bugs as the storage service version, specifically arbitrary file writes, due to the reverting call to MoveFileEx and arbitrary ACL setting by placing a hardlinked file in a directory with inheritable ACEs.

This method is called from DSSMoveToSharedFile and DSSMoveFromSharedFile. While those methods do some checking it’s still possible to bypass the checks. This results in the MoveFileInheritSecurity method being called as the SYSTEM user which results in EoP.

I’m saddened by the fact this wasn’t discovered during variant analysis from the Storage Service issues.

Proof of Concept:

I’ve provided a PoC as a C# project. It calls DSMoveFromSharedFile to modify the DACL of a hardlink arbitrary file granted write access to the user.

1) Compile the C# project. It’ll need to pull NtApiDotNet from NuGet to build.
2) Execute the PoC passing the path to a file the user can’t write on the command line (but can be written by SYSTEM).

Expected Result:
The call to move the file.


Observed Result:
The call to move file succeeds and the arbitrary file is now ACLS with the Everyone group for full access.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw

### CVE-2019-0566


Windows: Browser Broker Cross Session EoP
Platform: Windows 10 1803 (not tested anything else).
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): Session Boundary

Summary: 

The Browser Broker COM object doesn’t verify its caller correctly allowing one user to execute arbitrary code in another logged on user’s session.

Description:

The Browser Broker Class (CLSID: 0002df02-0000-0000-c000-000000000046) is closely tied with Microsoft Edge and is used to perform certain privileged operations that the main browser process running in an App Container cannot do. The majority of the calls are checked with functions such as BrokerAuthenticateAttachedCallerGetPIC which ensures the caller is an Edge process (based on its package ID) and meets certain requirements based on the sandbox type etc. One thing this code doesn’t do is check that the caller is the same user as the running broker process.

As the user is not checked this means it’s only the COM security which prevents you instantiating this in another running session on the same machine. The COM users allowed to launch the broker are:
* Everyone
* microsoft.microsoftedge_8wekyb3d8bbwe (package SID)

This means that everyone is allowed to start the broker COM process even in another session. However perhaps the access permissions will save us:

* NT AUTHORITY\Authenticated Users
* BUILTIN\Guests
* microsoft.microsoftedge_8wekyb3d8bbwe (package SID)
* NAMED CAPABILITIES\Lpac Web Platform

Even Guests can access the COM object after creating it (I’ve no idea why of all things). Basically though these sets of permissions ensure that one user can create and call methods on the broker in another session. The only requirement is you need to impersonate the Microsoft Edge token when calling methods, but that’s easy to get just by stealing the token from a running Edge process.

Once you’ve got access to the broker COM server it’s pretty easy to exploit to get arbitrary code execution. You can modify files through the IFileOperationBroker or just call ShellExecute using IDownloadExecutionBroker. 

Ultimately I warned you after cases 36544 and 37954 that you should be fixing the root cause of normal user’s being able to use the Session Moniker not playing whack-a-mole with COM objects. Of course you didn’t listen then and no doubt you’ll just try and fix browser broker and be done with it.

This issue also demonstrates that the Browser Broker is an easy sandbox escape if you can get into the MicrosoftEdge process, which doesn’t seem a good thing IMO. While LPAC certainly makes it harder to elevate to the main browser process I’d not be confident of it being a complete security boundary.

Proof of Concept:

I’ve provided a PoC as a C++ project. It will steal the access token from a running copy of Edge then restart itself in another logged on session.

1) Compile the C++ project.
2) Ensure there’s two users logged on to the same system.
3) Start Edge in the session you’ll run the PoC from.
4) Run the PoC.

Expected Result:
Create a broker and accessing it in another session should fail.

Observed Result:
The PoC is running in another user’s session.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.




Found by: forshaw

### CVE-2019-0552


Windows: COM Desktop Broker Elevation of Privilege
Platform: Windows 10 1809 (almost certainly earlier versions as well).
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): AppContainer Sandbox

Summary: 

The COM Desktop Broker doesn’t correctly check permissions resulting in elevation of privilege and sandbox escape.

Description:
Windows 10 introduced “Brokered Windows Runtime Components for side-loaded applications” which allows a UWP application to interact with privileged components by allowing developers to write a custom broker in .NET. Rather than handling this with the existing Runtime Broker a new “Desktop Broker” was created and plumbed into the COM infrastructure. This required changes in COMBASE to instantiate the broker class and RPCSS to control access to the broker.

The stated purpose is only for use by sideloaded enterprise applications, specifically .NET based ones. Looking at the checks in RPCSS for the activation of the broker we can see the check as follows:

HRESULT IsSideLoadedPackage(LPCWSTR *package_name, bool *is_sideloaded) {
  PackageOrigin origin;
  *is_sideloaded = false;
  HRESULT hr = GetStagedPackageOrigin(package_name, &origin);
  if (FAILED(hr))
    return hr;
  
  *is_sideloaded = origin != PackageOrigin_Store;
  return S_OK;
}

This check is interesting because it considered anything to be sideloaded that hasn’t come from the Store. Looking at the PackageOrigin enumeration this includes Inbox applications such as Cortana and Edge both of which process potentially untrusted content from the network. Of course this isn’t an issue if the broker is secure, but…

For a start, as long as RPCSS thinks the current package is side-loaded this feature doesn’t require any further capability to use, or at least nothing checks for one during the process. Even in the side loading case this isn’t ideal, it means that even though a side loaded application is in the sandbox this would allow the application to escape without giving the installer of the application any notice that it has effectively full trust. Contrast this with Desktop Bridge UWP applications which require the “fullTrust” capability to invoke a Win32 application outside the sandbox. This is even more important for a sandbox escape from an Inbox application as you can’t change the capabilities at all without having privileged access. Now, technically you’re supposed to have the appropriate configuration inside the application’s manifest to use this, but that only applies if you’re activating through standard COM Runtime activation routes, instead you can just create an instance of the broker’s class (which is stored in the registry, but at least seems to always be C8FFC414-946D-4E61-A302-9B9713F84448). This class is running in a DLL surrogate at normal user privileges. Therefore any issue with this interface is a sandbox escape. The call implements a single interface, IWinRTDesktopBroker, which looks like:

class IWinRTDesktopBroker : public IUnknown {
    HRESULT GetClassActivatorForApplication(HSTRING dir, IWinRTClassActivator** ppv);
};

This interface has only one method, GetClassActivatorForApplication which takes the path to the brokered components directory. No verification of this directory takes place, it can be anywhere you specify. I’d have assumed it might have at least been limited to a special subdirectory of the package installation, but I’d clearly be wrong. Passing an arbitrary directory to this method, you get back the following interface:

class IWinRTClassActivator : public IUnknown {
    HRESULT ActivateInstance(HSTRING activatableClassId, IInspectable** ppv);
    HRESULT GetActivationFactory(HSTRING activatableClassId, REFIID riid, IUnknown** ppv);
};

So to escape the sandbox with this you can create directory somewhere, copy in a WinRT component winmd file then activate it. The activation process will run class constructors and give you arbitrary code execution outside the sandbox. 

However, even if the directory was checked in some way as long as you can get back the IWinRTClassActivator interface you could still escape the sandbox as the object is actually an instance of the System.Runtime.InteropServices.WindowsRuntime.WinRTClassActivator class which is implemented by the .NET BCL. This means that it exposes a managed DCOM object to a low-privileged caller which is pretty simple to exploit using my old serialization attacks (e.g. MSRC case 37122). The funny thing is MSRC wrote a blog post [1] about not using Managed DCOM across security boundaries almost certainly before this code was implemented but clearly it wasn’t understood.
[1] <a href="https://blogs.technet.microsoft.com/srd/2014/10/14/more-details-about-cve-2014-4073-elevation-of-privilege-vulnerability/" title="" class="" rel="nofollow">https://blogs.technet.microsoft.com/srd/2014/10/14/more-details-about-cve-2014-4073-elevation-of-privilege-vulnerability/</a>

There are some caveats, as far as I can tell you can’t create this broker from an LPAC Edge content process, more because the connection to the broker fails rather than any activation permissions check. Therefore to exploit from Edge you’d need to get into the MicrosoftEdge process (or another process outside of LPAC). This is left as an exercise for the reader.

Fixing wise, I’d guess unless you’re actually using this for Inbox applications at a minimum you probably should only Developer and LOB origins. Ideally you’d probably want to require a capability for its use but the horse may have bolted on that one. Anyway you might not consider this an issue as it can’t easily be used from LPAC and side-loading is an issue unto itself.

Proof of Concept:

I’ve provided a PoC as a solution containing the C# PoC and Brokered Component as well as a DLL which can be injected into Edge to demonstrate the issue. The PoC will inject the DLL into a running MicrosoftEdge process and run the attack. Note that the PoC needs to know the relative location of the ntdll!LdrpKnownDllDirectoryHandle symbol for x64 in order to work. It should be set up for the initial release of RS5 (17763.1) but if you need to run it on another machine you’ll need to modify GetHandleAddress in the PoC to check the version string from NTDLL and return the appropriate location (you can get the offset in WinDBG using ‘? ntdll!LdrpKnownDllDirectoryHandle-ntdll). Also before you ask, the injection isn’t a CIG bypass you need to be able to create an image section from an arbitrary file to perform the injection which you can do inside a process running with CIG.

1) Compile the solution in “Release” mode for “Any CPU”. It’ll need to pull NtApiDotNet from NuGet to build.
2) Start a copy of Edge.
3) Execute the PoC from the x64\Release directory.

Expected Result:
Creating the broker fails.

Observed Result:
The broker creation succeeds and notepad executes outside the sandbox.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.




Found by: forshaw

### CVE-2019-0570


Windows: RestrictedErrorInfo Unmarshal Section Handle UAF EoP
Platform: Windows 10 1709/1809
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

Summary:
The WinRT RestrictedErrorInfo doesn’t correctly check the validity of a handle to a section object which results in closing an unrelated handle which can lead to EoP.

Description:
The RestrictedErrorInfo class is a COM object implemented internal to the COM runtime. It’s used to pass structured error information across WinRT apartment and process boundaries. For that reason it supports a custom marshaling protocol and as it’s part of the system infrastructure it also marked a system trusted marshaler. It can be sent to processes which explicitly prevent custom marshaling such as many system services as well as AppContainer processes. 

To send larger amounts of information such as the stack trace (and perhaps for security reasons) the marshaler will insert the name of a section object as well as a handle to that object into the marshaled stream. As COM marshaling doesn’t directly support passing handles, at least without additional help, the unmarshal code opens the client process and duplicates a SYNCHRONIZE only handle to the section into that process. The presumed idea behind passing this handle is it can be used to verify the section name is not some arbitrary section object. This validation takes place in the following code:

HRESULT CRestrictedError::ValidateHandle(
  HANDLE hSection, const wchar_t *pszSectionName, unsigned int cchSectionName)
{
  if ( !hSection && !*pszSectionName )
    return S_OK;
  ULONG length;
  NTSTATUS status = NtQueryObject(hSection, ObjectNameInformation, NULL, NULL, &length);
  if (status == STATUS_INFO_LENGTH_MISMATCH )
  {
    PUNICODE_STRING name = malloc(length);
    NtQueryObject(hSection, ObjectNameInformation, name, length, NULL);
    ULONG total_length = name->Length / 2;
      if (length < 60)
        return E_INVALID_ARG;
      LPWSTR str = name.Buffer[name->Length - 60 * 2];
      if (wmemcmp(L"RestrictedErrorObject-", str, 22))
        return E_INVALID_ARG;
      size_t name_length  = wcslen(pszSectionName);
      if (wmemcmp(pszSectionName, str, name_length))
        return E_INVALID_ARG;
      return S_OK;
  }
  return E_ERROR;
}

ValidateHandle takes the handle from the marshaled data and uses NtQueryObject to get its object name. This name, minus any leading name information is then compared against the passed in section name. If they’re not equal then this function fails and the section information is ignored. There’s two issues with this code, firstly it just checks the last 60 characters of the string matches “RestrictedErrorObject-” plus an arbitrary suffix. Secondly, and most importantly, it doesn’t verify that the handle is a section object, it just verifies the name. 

This might not be a major issue except that once the handle is validated the code assumes ownership of the handle. Therefore once the code is finished with the handle, which can be in the unmarshaler or when the RestrictedErrorInfo object is released, the handle will be closed. If the handle is set to a pre-existing handle inside the unmarshaling process, as long as it meets the name requirements the handle will be closed and the handle entry opened for reuse. This can lead to a UAF on an arbitrary handle.

One way of exploiting this would be to attack the BITS service which as demonstrated many times is a good privileged target for these sorts of attacks:

1) Create a job writing a file to the path “C:\RestrictedErrorObject-PADDING\OUTPUT.TXT”. This results in BITS creating a temporary file “C:\RestrictedErrorObject-PADDING\BITSXXXX.tmp”. 
2) Start the job and stall the GET request for the HTTP data, this is easy to do by requesting BITS downloads a URL from localhost and setting up a simple HTTP server.
3) BITS now has an open, writable handle to the temporary file which the last 60 characters is of the form “RestrictedErrorObject-PADDING\BITSXXXX.tmp”.
4 ) Marshal an error object, specifying the handle value for the temporary file (might have to brute force) and the section name using the name from 3. Send it to the BITS service using whatever mechanism is most appropriate. As the downloading is happening in a background thread the COM service is still accessible.
5) The unmarshaler will verify the handle then close the handle. This results in the stalled download thread having a stale handle to the temporary file.
6) Perform actions to replace the handle value with a different writable file, one which the user can’t normally write to.
7) Complete the GET request to unblock the download thread, the BITS service will now write arbitrary data to the handle. 

As the download thread will close the arbitrary handle, instead of 6 and 7 you could replace the handle with some other resource such as a token object and then get a UAF on a completely arbitrary handle type leading to other ways of exploiting the same bug.

From a fixing perspective you really should do a better job of verifying that the handle is a section object, although even that wouldn’t be foolproof.

Proof of Concept:

I’ve provided a PoC as a C# project. Note that this doesn’t do an end to end exploit, it just demonstrates the bug in the same process as it’s a more reliable demonstration. This shouldn’t be a problem but if you really can’t see this is a security issue then… The PoC will create a file which will match the required naming pattern, then insert that into the marshaled data. The data will then be unmarshaled and the handle checked. Note that I release the COM object explicitly rather than waiting for the garbage collector as the handle is only released when the underlying COM object is released. For an attack on a native service this would not be necessary, but it’s mostly a quirk of using C#.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Run the PoC.

Expected Result:
The unmarshal process should fail, or the handle is valid after the unmarshal process.

Observed Result:
The unmarshal process succeeds and the second call to obj.FullPath fails with an STATUS_INVALID_HANDLE error.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.




Found by: forshaw

### CVE-2019-0555


Windows: XmlDocument Insecure Sharing Elevation of Privilege
Platform: Windows 10 1809 (almost certainly earlier versions as well).
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): AppContainer Sandbox

Summary: 

A number of Partial Trust Windows Runtime classes expose the XmlDocument class across process boundaries to less privileged callers which in its current form can be used to elevate privileges and escape the Edge Content LPAC sandbox.

Description:

When an AppContainer sandboxed application creates a partial trust class it’s instantiated inside a Runtime Broker running at the normal user privilege. While Windows.Data.Xml.Dom.XmlDocument is marked as Base Trust so would be instantiated inside the same process as the creator, there’s a number of partial trust classes which expose a  XmlDocument object.

An example of this is the ToastNotificationManager class which expose a XmlDocument through the GetTemplateContent static method. This is exposed to all normal AC and also has explicit permissions to allow lpacAppExperience capability to access it which all Edge Content LPAC processes have.

The problem with XmlDocument is it doesn’t custom marshal the object over process boundaries, this means that the XmlDocument which is created by ToastNotificationManager stays in the Runtime Broker. If there’s any security issues with the use of XmlDocument interface then that’s a problem.

Looking at the class it’s implemented inside msxml6.dll and is basically a MSXML.DOMDocument.6.0 class in all but name. Checking what interfaces the class supports you find the following (partial list):

IPersistMoniker
IPersistStream
IPersistStreamInit
IServiceProvider
IStream
IXMLDOMDocument
IXMLDOMDocument2
IXMLDOMDocument3
IXMLDOMNode
Windows::Xml::Dom::IXmlDocument
Windows::Xml::Dom::IXmlDocumentIO
Windows::Xml::Dom::IXmlDocumentIO2
Windows::Xml::Dom::IXmlNode
Windows::Xml::Dom::IXmlNodeSelector
Windows::Xml::Dom::IXmlNodeSerializer

What sticks out is it supports IXMLDOMDocument* which is the normal MSXML interfaces. Even if the underlying implementation was based on the existing MSXML DOM Document I’d have expected that creating this object as a runtime object would wrap the MSXML object and only expose those interfaces needed for its use as a runtime object. However, it exposes everything. 

Potential issues with this are:
IPersistMoniker could be used to save to a file with normal user privileges.
IXMLDOMDocument supports a save method which can do the same thing.
You can access the transformNode method to execute an XSLT template including arbitrary WSH script code (this is the _really_ bad one).

So the easiest way to escape the sandbox would be to execute the XSLT script. As the script is running in the Runtime Broker it runs with full user privileges and so can trivially escape the sandbox including the Edge Content LPAC sandbox.

The other classes which expose an XmlDocument:

ToastNotification via the get_Content method.
BadgeUpdateManager via the GetTemplateContent method.
TileFlyoutUpdateManager again via GetTemplateContent.
TileUpdateManager...

You can work out the rest, I’ve got better things to do.

Note that I think even if you remove all non-runtime interfaces exposed from XmlDocument just the built in functionality might be dangerous. For example you can call XmlDocument::loadXML with the ResolveExternals load setting which would likely allow you to steal files from the local system (a local XXE attack basically). Also I’m not entirely convinced that SaveToFileAsync is 100% safe when used OOP. It just calls StorageFile::OpenAsync method, in theory if you could get a StorageFile object for a file you can’t write to, if there’s normally a check in OpenAsync then that could result it an arbitrary file being overwritten.

Fixing wise at the least I’d wrap XmlDocument better so that it only exposes runtime interfaces. In the general case I’d also consider exposing XmlDocument over a process boundary to be dangerous so you might want to try and do something about that. And alternative would be to implement IMarshal on the object to custom marshal the XML document across the process boundary so that any calls would only affect the local process, but that’d almost certainly introduce perf regressions as well as appcompat issues. But that’s not my problem.

Proof of Concept:

I’ve provided a PoC as a solution containing the C# PoC as well as a DLL which can be injected into Edge to demonstrate the issue. The PoC will inject the DLL into a running MicrosoftEdgeCP process and run the attack. Note that the PoC needs to know the relative location of the ntdll!LdrpKnownDllDirectoryHandle symbol for x64 in order to work. It should be set up for the initial release of RS5 (17763.1) but if you need to run it on another machine you’ll need to modify GetHandleAddress in the PoC to check the version string from NTDLL and return the appropriate location (you can get the offset in WinDBG using ‘? ntdll!LdrpKnownDllDirectoryHandle-ntdll). Also before you ask, the injection isn’t a CIG bypass you need to be able to create an image section from an arbitrary file to perform the injection which you can do inside a process running with CIG.

1) Compile the solution in “Release” mode for “Any CPU”. It’ll need to pull NtApiDotNet from NuGet to build.
2) Start a copy of Edge (ensure it’s not suspended).
3) Execute the PoC from the x64\Release directory.

Expected Result:
Accessing the XmlDocument provides no elevated privileges.

Observed Result:
Notepad executes outside the sandbox.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.




Found by: forshaw

### Related CVE Numbers: CVE-2019-0768.


Windows: Windows: IE11 VBScript execution policy bypass in MSHTML
Platform: Windows 10 1809 (not tested earlier)
Class: Security Feature Bypass

Summary:

MSHTML only checks for the CLSID associated with VBScript when blocking in the Internet Zone, but doesn't check other VBScript CLSIDs which allow a web page to bypass the security zone policy.

Description:
According to https://blogs.windows.com/msedgedev/2017/07/07/update-disabling-vbscript-internet-explorer-11/, Starting from Windows 10 Fall Creators Update, VBScript execution in IE 11 should be disabled for websites in the Internet Zone and the Restricted Sites Zone by default.

The check for the VBScript security zone policy is done in MSHTML!AllowVBScript which is only called from MSHTML!CScriptCollection::GetHolderCLSID if the script language CLSID matches {b54f3741-5b07-11cf-a4b0-00aa004a55e8}. However, IE still supports the old VBScript.Encode language which has a slightly different CLSID of {b54f3743-5b07-11cf-a4b0-00aa004a55e8}. Therefore to bypass the VBScript zone security policy it's possible to just change the language attribute in the HTML from \u"VBScript\u" to \u"VBScript.Encode\u". To add insult to injury you don't even need to encode the VBScript as if the engine detects the script is not encoded it tries to parse it as unencoded script.

Proof of Concept:

I've provided a PoC as a HTML file with a meta tag to force IE5 compatibility. Just host on an HTTP server.

1) Browse IE11 to the PoC on the web server.

Expected Result:
No VBScript is executed.

Observed Result:
VBScript is executed and a message box is displayed.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.


Found by: forshaw@google.com

### Related CVE Numbers: CVE-2018-5511.


VMware: Host VMX Process Impersonation Hijack EoP
Platform: VMware Workstation Windows v14.1.5 (on Windows 10). Also tested VMware Player 15.0.2.
Class: Elevation of Privilege

Summary:
 The creation of the VMX process on a Windows host can be hijacked leading to elevation of privilege.

Description: The VMX process (vmware-vmx.exe) process configures and hosts an instance of VM. As is common with desktop virtualization platforms the VM host usually has privileged access into the OS such as mapping physical memory which represents a security risk. To mitigate this the VMX process is created with an elevated integrity level by the authentication daemon (vmware-authd.exe) which runs at SYSTEM. This prevents a non-administrator user opening the process and abusing its elevated access.

Unfortunately the process is created as the desktop user and follows the common pattern of impersonating the user while calling CreateProcessAsUser. This is an issue as the user has the ability to replace any drive letter for themselves, which allows a non-admin user to hijack the path to the VMX executable, allowing the user to get arbitrary code running as a \u"trusted\u" VMX process. While having an elevated integrity level isn't especially dangerous, the fact that arbitrary code is running as a  \u"trusted\u" VMX process means you can access all the facilities for setting up VMs, such as the \u"opensecurable\u" command which allows the process to open almost any file as SYSTEM for arbitrary read/write access which could easily be used to get administrator privileges. Write file write access you could perform an attack similar to https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html. 

I reported the technique of hijacking process creation to Microsoft over 3 years ago (see https://bugs.chromium.org/p/project-zero/issues/detail?id=351). Unfortunately Microsoft declined to fix it at the time. This makes fixing this issue more difficult than it should be. You might think a a quick fix would be to not impersonate the user over the call to CreateProcessAsUser. However you can end up with other issues such as (https://bugs.chromium.org/p/project-zero/issues/detail?id=692). Also even if the user didn't hijack the main process creation they could instead hijack DLL's loaded by the VMX process once started. 

A more comprehensive fix would to not create the process as the desktop user, instead using another user identity, however that in itself has risks and makes things considerably more complex.

Proof of Concept:

I've provided a PoC as a C#/C++ project. The C# application will perform the hijack and get the C++ vmware-vmx process 

1) Compile the project. It will need to grab the NtApiDotNet from NuGet to work.
2) Ensure the compiled output directory has the files HijackVMXProcess.exe, NtApiDotNet.dll and vmware-vmx.exe.
3) Run HijackVMXProcess.exe. If successful you should find that instead of the installed version of vmware-vmx the fake one is running. You can also specify a path to HijackVMXProcess and the fake vmware-vmx will demonstrate opening the file using the opensecurable command for write access.

Expected Result:
The VMX process created is the version provided by VMWare.

Observed Result:
The VMX process is a fake one provided by the PoC which allows access to secured commands.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw@google.com

### Related CVE Numbers: CVE-2019-5512.


VMware: Host VMX Process COM Class Hijack EoP
Platform: VMware Workstation Windows v14.1.5 (on Windows 10). Also tested VMware Player 15.
Class: Elevation of Privilege

Summary:
 COM classes used by the VMX process on a Windows host can be hijacked leading to elevation of privilege.

Description: The VMX process (vmware-vmx.exe) process configures and hosts an instance of VM. As is common with desktop virtualization platforms the VM host usually has privileged access into the OS such as mapping physical memory which represents a security risk. To mitigate this the VMX process is created with an elevated integrity level by the authentication daemon (vmware-authd.exe) which runs at SYSTEM. This prevents a non-administrator user opening the process and abusing its elevated access.

Unfortunately the process is created as the desktop user which results in the elevated process sharing resources such as COM registrations with the normal user who can modify the registry to force an arbitrary DLL to be loaded into the VMX process. 

The COM classes observed to be loaded by the VMX process, and thus can be hijacked by modifying the registry  are as follows:

1b1cad8c-2dab-11d2-b604-00104b703efd Microsoft WBEM (non)Standard Marshaling for IEnumWbemClassObject
7c857801-7381-11cf-884d-00aa004b2e24 PSFactoryBuffer
8bc3f05e-d86b-11d0-a075-00c04fb68820 Windows Management and Instrumentation
bcde0395-e52f-467c-8e3d-c4579291692e MMDeviceEnumerator class
cb8555cc-9128-11d1-ad9b-00c04fd8fdff WbemAdministrativeLocator Class
d68af00a-29cb-43fa-8504-ce99a996d9ea Microsoft WBEM (non)Standard Marshaling for IWbemServices
e7d35cfa-348b-485e-b524-252725d697ca PSFactoryBuffer

The majority of these are related to WMI and are probably not critical so could be removed, however MMDeviceEnumerator is used to find audio devices which is probably important. Also note that hijacking COM classes isn't necessarily the only resource which could be hijacked. From a fixing perspective I don't know of any documented way of preventing the lookup of COM classes from HKEY_CURRENT_USER other than running the process as an administrator, about all you can do is not use COM at all. As with the other bug I've reported at the same time a more comprehensive fix would probably to not create the process as the desktop user, instead using another user identity, however that in itself has risks.

Proof of Concept:

I've provided a PoC as a C++ project. 

1) Compile the project, make sure to compile the x64 version of the DLL otherwise the PoC will fail.
2) Copy the compiled HijackDll.dll to the folder c:\\hijack. 
3) Install the hijack.reg file using REGEDIT or the command line REG tool. This setups up a hijack of the CB8555CC-9128-11D1-AD9B-00C04FD8FDFF class. 
4) Start a VMX instance using the normal GUI or vmrun.

Expected Result:
The system COM class is loaded into the VMX.

Observed Result:
The VMX process loads the hijack DLL into memory and a dialog box appears proving the code injection.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw@google.com

### Related CVE Numbers: CVE-2019-0735.


Windows: CSRSS SxSSrv Cached Manifest EoP
Platform: Windows 10 1809, 1709
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary (and others)

Summary:

The SxS manifest cache in CSRSS uses a weak key allowing an attacker to fill a cache entry for a system binary leading to EoP.

Description:
Manifest files are stored as XML, typically inside the PE resource section. To avoid having to parse the XML file each time a process starts CSRSS caches the parsed activation context binary format in a simple database. This cache can be queried during process startup or library loading by calling into CSRSS via CsrClientCall resulting in calls to BaseSrvSxsCreateProcess or BaseSrvSxsCreateActivationContext inside SXSSRV.DLL. 

The database is an AVL tree and uses the function BaseSrvActivationContextCacheCompareEntries to identify a hit or miss in the cache. The comparison function only checks the Win32 path to the file, the Win32 base path, the language string, the last write timestamp of the executable and some flags. BaseSrvSxsCreateProcess which is sent during process creation in CreateProcessInternal via the call to BasepConstructSxsCreateProcessMessage queries the cache for a new process, adding an entry to the cache if it doesn't already exist. All the values used by the cache seem to be passed to BasepConstructSxsCreateProcessMessage with no further checking taking place. If an executable does not have a cached manifest entry a process can trivially add their own entry into the cache which would match against another executable file on the system. Once CSRSS has processed the manifest it'll map the binary activation context into the new process' memory and update the ActivationContextData value in the PEB so that it can be used.

Adding an arbitrary cache entry is a problem as the keying doesn't take into account the different privilege levels in the same session. For example it should be possible to use this to escape a sandbox by filling in a cache entry for a process that will run at normal user privilege, when that process starts it'll get the arbitrary cache entry allowing the attacker to hijack COM classes or redirect DLLs. There doesn't seem to be any AppContainer specific flags (but I could have missed them). This is also a, relatively, trivial UAC bypass but of course that's not a security boundary.

Polluting the cache for the user's session doesn't impact other sessions. Session 0 would be an interesting target, however in theory it's not directly accessible and trying to connect to CSRSS's ALPC port is rejected. If you have an arbitrary Session 0 code execution bug (such as case 47812) then you could access CSRSS but can it be done without any futher bugs? There's a quirk in the handling of BaseSrvSxsCreateProcess. The call is made from the session of the process which is creating the new process, not the session of the new process. This means that any Session 0 service which creates user processes in other sessions will cache the manifest of that file in Session 0 CSRSS. Without directly calling CSRSS how can the arbitrary cache entry be created? 

The data passed to CSRSS is based on the data passed to CreateProcess, for example if you execute c:\\windows\\system32\\abc.exe then that's what's passed to the cache, this it turns out can be hijacked, as most privileged process creation impersonates the caller (otherwise there might be a security bug) then a normal user can hijack the system drive during CreateProcess. By redirecting the system drive to an arbitrary directory the manifest data is parsed from an arbitrary executable, but the keying information passed to CSRSS is based on what the service thinks it's created. Turns out this is made all the easier as you Wont Fixed this exactly problem 3 years ago in case MSRC 30096, oops. 

To summarise to exploit this issue for user to privileged process in Session 0 you do the following:
1. Find an executable which meets the following criteria
* Can be started by a normal user account and runs in session 0 as a privileged user. COM, services or scheduled tasks are usually good places to look for targets.
* The executable file has an embedded manifest, if the file doesn't have a manifest then the cached manifest is not parsed or applied.
* The executable doesn't get run very often, once the executable has been cached it's hard to clear that entry again from a normal user account. You can modify a registry value in HKLM and it might be updated if an installer runs but I didn't investigate this in detail.

2. Create an executable with a manifest which redirects a COM registration or similar to an arbitrary path, place in a temporary directory with the path information from the the file in 1. E.g. if you want to hijack c:\\windows\\system32\\abc.exe, create the directory %TEMP%\\windows\\system32 and copy the executable as abc.exe. Clone the last write timestamp from the target file to the newly copied file.
3. Redirect the system drive to the temporary folder, when opening the file under impersonation it will be redirected to the executable with the target manifest.
4. Start the process using a service in Session 0 which will also impersonate during creation. WMI Win32_Process::Create is perfect for this.
5. Once cached start the original executable as the privileged user and induce it to load the hijacked COM class.

One quirk is when the XML file is parsed it doesn't allow parent relative paths for DLLs, although it will allowing child relative (i.e. ..\\..\\abc.dll is blocked but test\\abc.dll is allowed). This quirk can be circumvented by modifying the binary data before registering it with CSRSS, as the XML file is parsed in the creating process for a sandbox escape. For exploiting session 0 we can just pick a directory the user can write to relative to system32, Tasks is a good a place as any.

Proof of Concept:

I've provided a PoC as a C# project and C++ DLL. The PoC hijacks the CoFilterPipeline Class which is implemented in printfilterpipelinesvc.exe. This only runs as LOCAL SERVICE, but that includes Impersonate and Assign Primary Token privileges which is effectively admin. It was the best I could find at short notice as most of the other targets were used regularly which prevented the user from hijacking the cached entry. When the COM class is created is can be hijacked by querying for one of it's interfaces, this results in loading the proxy class which the manifest redirects to the file \u"tasks\\hijack\\hijack.dll\u", as printfilterpipelinesvc is in System32 this results in a controlled DLL being loaded into process.

1) Compile the C# project in Release for \u"Any CPU\u". It will need to grab the NtApiDotNet from NuGet to work.
2) Run the PoC_ExpoitManifestCache.exe from x64\\Release folder, ensuring the folder also contains hijack.dll. 

If the PoC fails with \u"Query succeeded, likely we couldn't hijack the proxy class\u" or \"Cached manifest not used, perhaps we were too late?\" It means that the printfilterpipelinesvc must have been run in session 0 previously. To test reboot the machine and try again as that should clear the cache. I don't know if the cache gets cleared with power-off and power-on due to the fast boot features.

Expected Result:
The manifest file is not used by the privileged process.

Observed Result:
The manifest file is hijacked, an arbitrary DLL is loaded into a privileged process and a copy of notepad is started at LOCAL SERVICE.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw@google.com

### Related CVE Numbers: CVE-2019-0730.


Windows: LUAFV Delayed Virtualization MAXIMUM_ACCESS DesiredAccess EoP
Platform: Windows 10 1809 (not tested earlier)
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

Summary:
 

The LUAFV driver reuses the file's create request DesiredAccess parameter, which can include MAXIMUM_ACCESS, when virtualizing a file resulting in EoP.

Description:

The LUAFV is an enabled by default file system filter driver introduced in Windows Vista to support old applications which write to administrative locations such a System32 by virtualizing file access when certain criteria are met. The initial criteria is the process' token needs to have the VirtualizationEnabled flag set to TRUE. This is done automatically for certain process types for app-compat but can be changed through NtSetInformationToken as long as the VirtualizationAllowed flag is also TRUE. This is the case for all normal users, even on Windows 10 1809.

Outside of the token enable flag the file being opened must also meet a set of criteria:
1) The file being opened is in one of a number of protected locations.
2) The file can't be owned by TrustedInstaller, but must have an ACE which grants the administrator full access.
3) The file name must not have one of a number of banned extensions, such as .exe.
4) The caller must be denied one of a set of write accesses when opening the file.

If the file is virtualized a copy of the real file or directory is placed in the user's VirtualStore inside %LOCALAPPDATA%, however for performance reasons (presumably) the driver won't always do the copy immediately. If a caller's file creation request meets the four criteria for a file which already exists, but a copy does not currently exist in the VirtualStore then the driver enables Delayed Virtualization on the file. This results in the file being opened with the requested access rights with the original file opened with read only access. If a caller only uses the handle for read operations then those requests are serviced by the original file. If the caller makes a \u"write\u" request such as writing to the file or mapping the file writable then the virtualization kicks in, generating the file in the VirtualStore, opening that new file for the original write access and modifies the FILE_OBJECT's context to now read and write to the new virtualized file. The original FILE_OBJECT can't be replaced (unlike if the store file already exists which can be dealt with using a reparse operation from the filter) therefore many of the original properties of the \u"fake\u" file handle persist such as the granted access.

The vulnerability occurs in this process because during the initial filter process in LuafvPostCreate where delayed virtualization is setup the driver stores the SecurityContext->DesiredAccess as the requested access. This captured access is then used in LuafvPerformDelayedVirtualization when opening the newly created store file. As it's possible to specify MAXIMUM_ACCESS as the DesiredAccess this results in the \u"fake\u" FILE_OBJECT's handle access being set to FILE_ALL_ACCESS. When opening the store file MAXIMUM_ACCESS could result in a lower set access of access rights, however as the original FILE_OBJECT's handle can't be changed the caller can now pass file operations to the \u"fake\u" file and the driver will redirect them to the store file without further checking. Meaning if only read access was granted on the store file the user could bypass that and write to it.

You can't just pass MAXIMUM_ALLOWED on its own during file creation as the driver wouldn't see that as meeting criteria 4. So you also need to also pass one of the banned write access rights in DesiredAccess. However for the exploit to work this must also be granted on the store file so redirecting the create to an arbitrary location (using say a mount point) isn't sufficient. However there's two important things to observe:
1) As long as using the FILE_OPEN_IF disposition DELETE is a considered a banned write access.
2) A hardlink to a non-writable file can be created as a normal user. As long as the user has FILE_DELETE_CHILD on the directory containing the link then they'll also be granted DELETE on the target file.

Therefore we can exploit this by doing the following:
1) Enable virtualization on the token (this works in 32 or 64 bit processes)
2) Open an existing file which would meet the rest of the virtualization criteria and isn't currently virtualized with MAXIMUM_ALLOWED | DELETE as the access mask and FILE_OPEN_IF as the disposition.
3) Once opened the handle's granted access will be FILE_ALL_ACCESS. 
4) Create the target virtualized directory in %LOCALAPPDATA% and add a hardlink to a file to write to as the target virtualized name.
5) Perform an operation on the \u"fake\u" file handle to cause virtualization to occur, such as sending an FSCONTROL. The driver will try and virtualize the file, notice the file already exists and then open the hardlink with MAXIMUM_ALLOWED | DELETE. As DELETE is allowed this will return a read only handle with DELETE access.
6) Write to the \u"fake\u" file handle, as the handle has write access this will pass through the initial system call layers. The driver will then forward the request to the virtual file which was opened only for read but will complete successfully allowing the caller to modify a file they can't normally write to.

Fixing wise the new store file should be opened with the matching granted access on the original \u"fake\u" file handle. That way there can be no mismatch between the access granted on the \u"fake\u" handle and the backing virtual store file. It would also be interesting to know how often file virtualization is needed on modern systems and whether you could just remove it entirely.

These operations can't be done from any sandbox that I know of so it's only a user to system privilege escalation. 

Proof of Concept:

I've provided a PoC as a C# project. It will overwrite an existing file on the disk with arbitrary contents.

1) Compile the C# project. It'll need to pull NtApiDotNet from NuGet to build.
2) As a normal user run the PoC and pass the path to a file to overwrite on the same drive as the virtual store. To prove it works the file should not be writable by the user normally. Note that the file needs to be shareable for write access otherwise it'll fail due to the sharing violation.

Expected Result:
The virtualization operation fails.

Observed Result:
The virtualization operation succeeds with the string \u"FAKE CONTENT\u" written to the file.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw@google.com

### Related CVE Numbers: CVE-2019-0731.


Windows: LUAFV Delayed Virtualization Cross Process Handle Duplication EoP
Platform: Windows 10 1809 (not tested earlier)
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

Summary:
 

The LUAFV driver doesn't take into account a virtualized handle being duplicated to a more privileged process resulting in EoP.

Description:

When a caller creates the virtualized file handle the process token is checked for VirtualizationEnabled. If the flag is set and the file create request meets all the criteria for delayed virtualization the driver collates all the necessary information such as the virtual store location for the resulting file if it needs to be copied and stores it in the file object's context.

When a caller performs an operation on the file which is considered a write action, such as writing or issuing any FsControl request then the method LuafvPreWrite is called which will call LuafvPerformDelayedVirtualization. This results in the store file being created and the contents of the original file copied into the new store file before assigning the new file to the original \u"fake\u" file object so that the user can continue to use the file.

The vulnerability occurs during LuafvPerformDelayedVirtualization. The driver doesn't take into account the possibility that the virtualized file handle has been duplicated to a new process, specifically one which runs at higher privileges. For example if a normal user application creates the virtualized file, but then gets a SYSTEM service to duplicate the handle to itself and call one of the mechanisms to trigger LuafvPerformDelayedVirtualization the file creation will run as the SYSTEM user not the original user, but the path to the file will be the original user's virtual store.

Examples of possible duplicate primitives would be RPC/COM services which duplicate the handle either explicitly through the system_handle RPC attribute or manually by querying for the caller's PID and calling DuplicateHandle. Another would be a kernel driver which opens a handle in the current user's context (or takes a handle parameter) but passes that handle to a system thread for a long running operation. In both these cases the file operation does have to occur without the privileged service impersonating the original caller.

You can exploit this behavior in at least two ways. Firstly you could replace the virtual store directory with a mount point. When the virtualization process goes to create the final file it will follow the mount point and create the file in an arbitrary location. The contents of the file are completely controllable by the caller, but even if the privileged code overwrites part of the file the original opened handle can be used to get write access to the file afterwards. The second way would be to drop a hardlink to a file that the privileged service can write to in the virtual store, then when the file is opened by the service it becomes possible for the original caller to modify the file.

Fixing wise I'd probably double check something in LuafvPerformDelayedVirtualization before continuing with the file copy. Perhaps something as simple as user SID + IL would be sufficient, or only for users in the same authentication session as that would even prevent its abuse in UAC cases.

These operations can't be done from any sandbox that I know of so it's only a user privilege escalation. Note that the user which manipulates the duplicated handle doesn't need to be an admin, as it'd be possible to modify files owned by that user so it might be possible to abuse this for cross-session or LOCAL SERVICE/NETWORK SERVICE attacks.

Proof of Concept:

I've provided a PoC as a C# project. It will create the file dummy.txt with arbitrary contents inside the windows folder. Note that this PoC is manual, I've not gone through and worked out a system service which will perform the necessary operations but I'm confident one will exist as handle duplication is a fairly common technique and you don't even need to write to the file just perform one of the known actions.

1) Compile the C# project. It'll need to pull NtApiDotNet from NuGet to build.
2) As a normal user run the PoC. If there are no errors you should see the line: \u"Re-run the PoC as an admin with arguments - X Y\u".
3) Run as the PoC again as an admin, passing X and Y as arguments from step 2. This admin can be SYSTEM, it doesn't matter what session or user it runs as.

Expected Result:
The virtualization operation fails.

Observed Result:
The virtualization operation succeeds and the file c:\\windows\\dummy.txt is created with arbitrary contents.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.


Found by: forshaw@google.com

### Related CVE Numbers: CVE-2019-0796.


Windows: LUAFV LuafvCopyShortName Arbitrary Short Name EoP
Platform: Windows 10 1809 (not tested earlier)
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

Summary:
 

The LUAFV driver bypasses security checks to copy short names during file virtualization which can be tricked into writing an arbitrary short name leading to EoP.

Description:

When creating a virtualized file in LuafvCopyFile one of the things that the driver copies across is the short name of the original file by calling LuafvCopyShortName. This uses the FileShortNameInformation information class to set the short name, however the problem with using this is it normally requires SeRestorePrivilege to be enabled, which a non-administrator won't have access to. Therefore to bypass the privilege check the virtualized file is reopened without security checks, which results in the check being ignored.

The code looks roughly like the following:

NSTATUS LuafvCopyShortName(PFLT_INSTANCE Instance, 
                                                     PFILE_OBJECT ReadObject, 
                                                     HANDLE WriteHandle) {
  HANDLE FileHandle;
  PFILE_OBJECT WriteObject;
  NTSTATUS = FltCreateFileEx2(
          LuafvDriverData,
          Instance,
          &FileHandle,
          &WriteObject,
          FILE_WRITE_ATTRIBUTES,
          ...,
          IO_NO_PARAMETER_CHECKING);
  FILE_NAME_INFORMATION Name = {};
  if (NT_SUCCESS(status)) {
    if (NT_SUCCESS(FltQueryInformationFile(Instance, ReadHandle, &Name, sizeof(Name), 
                             FileAlternateNameInformation))) {
        status = FltSetInformationFile(Instance, WriteObject, 
            &Name, IoStatusBlock.Information, FileShortNameInformation);
     }
  }
  return status;
}

We can see in the code the writable file is re-opened with new access and without specifying IO_FORCE_ACCESS_CHECK. As FILE_OPEN_FOR_BACKUP_INTENT is specified then NTFS will mark this file as having restore privilege, even though the caller doesn't, as the previous mode will be KernelMode. The original file is then queried for its alternate name (which is really its short name) and the short name is set through the FileShortNameInformation which will now succeed due to the way the file handle was opened.

Of course the question is how would you get this code to write an arbitrary short name? Although it's not obvious if the name of the file is already a short name (as in a 8.3 DOS compatible name) then FileAlternateNameInformation doesn't fail but returns the normal file name back to the caller. Therefore we can exploit this as follows:

1) Create a file with the arbitrary short name inside a directory which is virtualized, ProgramData is ideal for this as we can create arbitrary files. Make the file writeable only to administrators.
2) Open the file for virtualization, but don't do anything to cause delayed virtualization to occur.
3) Use some symbolic tricks in the VirtualStore directory to cause the creation of that file to be redirected to a long name which would normally have an auto-generated short name.
4) Force the delayed virtualization to occur, the file with the long name will be created, however the short name will be read from the source file which has an arbitrary name. The short name is written bypassing security checks.

There's probably other ways of doing this without symbolic link tricks, for example there's a race between the time the file is opened and when the short name is queries. As the file is opened with FILE_SHARE_DELETE it should be possible to rename the source file between the initial open but before reading the short name.

What you could do with this ability is another matter. You could possibly trick some parsing operation which is relying on short names. Or you could create a directory which had two \u"normal\u" names rather than one auto generated one which could trick certain things. At any rate the EoP is the fact we can do this without needing SeRestorePrivilege.

I'm not going to speculate on how to fix this, as said while you might be able to block mount point traversal (seems unlikely as the user's profile could be on a remote share or another drive) there's probably other ways around this. 

Proof of Concept:

I've provided a PoC as a C# project. It will create an arbitrary file with an arbitrary short file name.

1) Compile the C# project. It'll need to pull NtApiDotNet from NuGet to build.
2) As a normal user run the PoC passing the name of the target file to create (with a long file name) and the arbitrary short file name.

Expected Result:
The virtualization operation fails.

Observed Result:
The virtualization operation succeeds and the file has an arbitrary short name.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw@google.com

### Related CVE Numbers: CVE-2019-0732.


Windows: LUAFV NtSetCachedSigningLevel Device Guard Bypass
Platform: Windows 10 1809 (not tested earlier). Note I've not tested this on Windows 10 SMode.
Class: Security Feature Bypass

Summary:
 

The NtSetCachedSigningLevel system call can be tricked by the operation of LUAFV to apply a cached signature to an arbitrary file leading to a bypass of code signing enforcement under UMCI with Device Guard.

Description:

As I've hit this API multiple times by now I'm not going to explain its operation. The novel aspect of this issue is that you can get the LUAFV driver to win the signing race between reading the file to determine the hash to sign and the file the kernel EA is assigned to.

The exploit is as follows:

1) Create a file with the contents of a valid Microsoft signed file, such as notepad.exe in a virtualized location.
2) Get LUAFV to virtualize that file by requesting DELETE access. DELETE is not considered a write access right for the purposes of any checks in the signing process.
3) Copy the unsigned executable to the virtual store with the target virtualized name.
4) Call NtSetCachedSigningLevel on the virtualized file specifying flag 4. 

This sequence results in the signing code reading the virtualized file, which contains the contents of notepad.exe and generating the signature based on that data. However when it goes to write the kernel EA the LUAFV driver considers that a write operation and virtualizes the file underneath. As we've created an arbitrary file in the virtual store the driver binds the file object to the unsigned file before writing out the kernel EA. This results in the EA going to the unsigned file rather than the original signed file. As you can't virtualize files with executable extensions you must ensure the signed file has an allowed extension, however once you've signed the file you can rename it to something more appropriate.

Note that I have checked that Windows 10 Pro SMode does load the LUAFV driver, however I've not checked that this bypass will work on it (but no reason to believe it doesn't).

Proof of Concept:

I've provided a PoC as a C# project. It will sign an arbitrary DLL file the map it into memory with the Microsoft only signature mitigation enabled.

1) Compile the C# project. It'll need to pull NtApiDotNet from NuGet to build.
2) As a normal user run the PoC passing the path to an unsigned DLL which will do something noticeable in DllMain (such as popping a message box).

Expected Result:
The cached signature operation fails.

Observed Result:
The an arbitrary file is cached signed and can be loaded with an elevated process signature level.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw@google.com

```
1: kd> !analyze -v
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE (162)
A lock tracked by AutoBoost was released by a thread that did not own the lock.
This is typically caused when some thread releases a lock on behalf of another
thread (which is not legal with AutoBoost tracking enabled) or when some thread
tries to release a lock it no longer owns.
Arguments:
Arg1: ffffdc05983e0080, The address of the thread
Arg2: ffffdc05a813f258, The lock address
Arg3: 00000000ffffffff, The session ID of the thread
Arg4: 0000000000000000, Reserved

Debugging Details:
------------------

BUILD_VERSION_STRING:  17763.1.amd64fre.rs5_release.180914-1434
BUGCHECK_P1: ffffdc05983e0080

BUGCHECK_P2: ffffdc05a813f258

BUGCHECK_P3: ffffffff

BUGCHECK_P4: 0

CPU_COUNT: 8

CPU_MHZ: af1

CPU_VENDOR:  GenuineIntel

CPU_FAMILY: 6

CPU_MODEL: 3e

CPU_STEPPING: 4

CPU_MICROCODE: 6,3e,4,0 (F,M,S,R)  SIG: 428'00000000 (cache) 428'00000000 (init)

DEFAULT_BUCKET_ID:  WIN8_DRIVER_FAULT

BUGCHECK_STR:  0x162

PROCESS_NAME:  PoC_LUAFV_Crash.exe

CURRENT_IRQL:  0

ANALYSIS_SESSION_HOST:  DEMO

ANALYSIS_SESSION_TIME:  01-30-2019 19:46:06.0019

ANALYSIS_VERSION: 10.0.17763.1 amd64fre

MANAGED_CODE: 1

MANAGED_ENGINE_MODULE:  clr

MANAGED_ANALYSIS_PROVIDER:  SOS

MANAGED_THREAD_ID: 2

LAST_CONTROL_TRANSFER:  from fffff801088a3cb2 to fffff801087cd7a0

STACK_TEXT:  
ffffee00`ee7a2e78 fffff801`088a3cb2 : ffffdc05`983e0080 00000000`00000003 ffffee00`ee7a2fe0 fffff801`0876e970 : nt!DbgBreakPointWithStatus
ffffee00`ee7a2e80 fffff801`088a3437 : 00000000`00000003 ffffee00`ee7a2fe0 fffff801`087d9b60 00000000`00000162 : nt!KiBugCheckDebugBreak+0x12
ffffee00`ee7a2ee0 fffff801`087c5c47 : ffffffff`ffffffff ffffee00`ee7a37c8 00000000`00000000 00001000`00000200 : nt!KeBugCheck2+0x957
ffffee00`ee7a3600 fffff801`087e1819 : 00000000`00000162 ffffdc05`983e0080 ffffdc05`a813f258 00000000`ffffffff : nt!KeBugCheckEx+0x107
ffffee00`ee7a3640 fffff801`086ab19f : 00000000`00000000 00000000`00000000 00000000`00000002 00000000`00000002 : nt!KeAbPostRelease+0xb2f29
ffffee00`ee7a36a0 fffff801`08c9a047 : ffffee00`ee7a3840 ffffdc05`983e0080 00000000`00000002 00000000`c0000428 : nt!MiZeroSectionObjectPointer+0x2f
ffffee00`ee7a36d0 fffff801`08c995bf : ffffdc05`aba8e9a0 ffffb08d`667230e0 ffffdc05`9b91f9e0 00000000`00000000 : nt!MiCreateImageOrDataSection+0x397
ffffee00`ee7a37c0 fffff801`08c99398 : 00000000`01000000 ffffee00`ee7a3b80 00000000`00000001 00000000`00000010 : nt!MiCreateSection+0xff
ffffee00`ee7a3940 fffff801`08c99194 : 00000009`43afed30 00000000`02000000 00000009`43afec40 00000000`00000000 : nt!MiCreateSectionCommon+0x1f8
ffffee00`ee7a3a20 fffff801`087d6d85 : ffffee00`ee7a3b80 fffff801`08c4cb9b 00000000`00000000 00000009`43afd148 : nt!NtCreateSection+0x54
ffffee00`ee7a3a90 00007ffe`aa13ffa4 : 00007ffe`17298a46 00000000`02000000 00000009`43afec40 00000009`43afed20 : nt!KiSystemServiceCopyEnd+0x25
00000009`43afebf8 00007ffe`17298a46 : 00000000`02000000 00000009`43afec40 00000009`43afed20 000001af`b88720c0 : ntdll!NtCreateSection+0x14
00000009`43afec00 00000000`02000000 : 00000009`43afec40 00000009`43afed20 000001af`b88720c0 00000000`00000010 : 0x00007ffe`17298a46
00000009`43afec08 00000009`43afec40 : 00000009`43afed20 000001af`b88720c0 00000000`00000010 00000000`01000000 : 0x2000000
00000009`43afec10 00000009`43afed20 : 000001af`b88720c0 00000000`00000010 00000000`01000000 00000000`00000340 : 0x00000009`43afec40
00000009`43afec18 000001af`b88720c0 : 00000000`00000010 00000000`01000000 00000000`00000340 00000000`02000000 : 0x00000009`43afed20
00000009`43afec20 00000000`00000010 : 00000000`01000000 00000000`00000340 00000000`02000000 00000000`00000030 : 0x000001af`b88720c0
00000009`43afec28 00000000`01000000 : 00000000`00000340 00000000`02000000 00000000`00000030 00000000`00000000 : 0x10
00000009`43afec30 00000000`00000340 : 00000000`02000000 00000000`00000030 00000000`00000000 00000000`00000000 : 0x1000000
00000009`43afec38 00000000`02000000 : 00000000`00000030 00000000`00000000 00000000`00000000 00000000`00000040 : 0x340
00000009`43afec40 00000000`00000030 : 00000000`00000000 00000000`00000000 00000000`00000040 00000000`00000000 : 0x2000000
00000009`43afec48 00000000`00000000 : 00000000`00000000 00000000`00000040 00000000`00000000 00000000`00000000 : 0x30


THREAD_SHA1_HASH_MOD_FUNC:  b6145e404036bb3336dbe1a09fb44bff34c46a37

THREAD_SHA1_HASH_MOD_FUNC_OFFSET:  269d3fc58bc0e80c68b757fdbf0c27dcb7e1ec38

THREAD_SHA1_HASH_MOD:  71f88233f75d3a6ee2c211b0292521c262eb12ae

FOLLOWUP_IP: 
nt!KeAbPostRelease+b2f29
fffff801`087e1819 cc              int     3

FAULT_INSTR_CODE:  8ffff0cc

SYMBOL_STACK_INDEX:  4

SYMBOL_NAME:  nt!KeAbPostRelease+b2f29

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: nt

IMAGE_NAME:  ntkrnlmp.exe

DEBUG_FLR_IMAGE_TIMESTAMP:  0

STACK_COMMAND:  .thread ; .cxr ; kb

BUCKET_ID_FUNC_OFFSET:  b2f29

FAILURE_BUCKET_ID:  0x162_nt!KeAbPostRelease

BUCKET_ID:  0x162_nt!KeAbPostRelease

PRIMARY_PROBLEM_CLASS:  0x162_nt!KeAbPostRelease

TARGET_TIME:  2019-01-30T19:43:12.000Z

OSBUILD:  17763

OSSERVICEPACK:  0

SERVICEPACK_NUMBER: 0

OS_REVISION: 0

SUITE_MASK:  272

PRODUCT_TYPE:  1

OSPLATFORM_TYPE:  x64

OSNAME:  Windows 10

OSEDITION:  Windows 10 WinNt TerminalServer SingleUserTS

OS_LOCALE:  

USER_LCID:  0

OSBUILD_TIMESTAMP:  unknown_date

BUILDDATESTAMP_STR:  180914-1434

BUILDLAB_STR:  rs5_release

BUILDOSVER_STR:  10.0.17763.1.amd64fre.rs5_release.180914-1434

ANALYSIS_SESSION_ELAPSED_TIME:  887

ANALYSIS_SOURCE:  KM

FAILURE_ID_HASH_STRING:  km:0x162_nt!keabpostrelease

FAILURE_ID_HASH:  {b939a70d-6d74-7d7d-94c9-2a7b2f9e3520}

Followup:     MachineOwner
---------

Windows: LUAFV Delayed Virtualization Cache Manager Poisoning EoP 

Related CVE Numbers: CVE-2019-0805.


Windows: LUAFV Delayed Virtualization Cache Manager Poisoning EoP
Platform: Windows 10 1809 (not tested earlier)
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

Summary:
 

The LUAFV driver can confuse the cache and memory manager to replace the contents of privileged file leading to EoP.

Description:

NOTE: This is different from issue 49895, that opens a backing file which could be overwritten as it wasn't opened with the correct permissions. This issue instead replaces the cache data for an existing system file. Also note the additional section at the end which describes how this issue also causes a Bug Check. I'm not convinced it's exploitable so I'm not reporting it separately.

The LUAFV driver supports many normal file operations to make virtualization as seamless as possible. This includes supporting memory mapping the file. When using delayed virtualization the driver allows mapping the original file read-only (as a data section or image section) without automatically creating the file in the virtual store. This trick is achieved by copying the real file's SECTION_OBJECT_POINTERS (SOP) pointer from the file object opened in LuafvDelayOrVirtualizeFile to the top-level \u"virtual\u" file object. 

When creating a new section for a file object the kernel calls MiCreateImageOrDataSection. After checking some parameters it calls MiCallCreateSectionFilters. This is important for virtualization as this results in calling LuafvPreAcquireForSectionSynchronization in the LUAFV driver. If that function detects that the caller is trying to map the section writable then LuafvPreWrite is called which will complete the delayed virtualization process, and will update the SOP pointer of the \u"virtual\u" file to the newly created backing file. If the file is not being mapped writable then the LUAFV driver leaves the SOP pointing to the \u"real\u" file.

MiCreateImageOrDataSection then checks whether the SOP::DataSectionObject CONTROL_AREA is populated. If not the kernel calls into MiCreateNewSection to setup a new one otherwise it'll try and reuse the existing one which is present in the \u"virtual\u" file. If a new CONTROL_AREA is created it contains a reference to the \u"virtual\u" file, not the underlying system file. This control area gets written into the SOP structure of the \u"virtual\u" file, which when performing a read-only mapping results in writing to the SOP structure of the underlying \u"real\u" file. 

The SOP structure is the responsibility of the filesystem driver, so when opening an NTFS file it's the NTFS driver which allocates and sets up this pointer. However the contents of the structure are the responsibility of the cache manager. In order to support sharing mappings, especially for image mappings, the NTFS driver ensures that the same file in a volume returns the same SOP structure even if the FILE_OBJECT pointer is different. This is where the bug lies, perhaps it's easier to explain how to exploit this:

1) Open a file for read/write access which will be delay virtualized. For example a file in system32 which isn't owned by TrustedInstaller.
2) Create a read-only section based on the virtualized file. As this is read-only the LuafvPreAcquireForSectionSynchronization function won't complete the delayed virtualization. Do not map the section.
3) As long as the file doesn't already have a DataSectionObject entry (likely if the file's never opened/read from) then a new CONTROL_AREA is created, backed by the \u"virtual\u" file.
4) Now cause the delayed virtualization process to complete, by sending an FSCONTROL code. The \u"virtual\u" file is now backed by a file in the virtual store which can be modified by the user, and the \u"virtual\u" file's SOP is replaced accordingly. However the DataSectionObject in the \u"real\u" file's SOP still refers to the virtual file. Now when reading data from the \u"real\u" file handle (even one opened directly without virtualization) the cache manager reads page contents from virtual store file, not the real file.

Once you've replaced a system file you can get direct EoP by replacing with the contents with a  PE file which can be loaded using services such as the \u"Diagnostics Hub Standard Collector Service\u" which I've detailed before. This works because the exploit has replaced the cache for that file and as its shared between all FILE_OBJECT instances (at least until the cache cleans it up) then the image section is created backed on the cached data. The replaced file contents will be also be returned for direct reads, the file doesn't have to be mapped to return the poisoned cache data.

One limitation to this vulnerability is you can't extend the length of the file, but there are suitable files in system32 which can contain a suitably small PE file to perform the full exploit. Note that it also doesn't really overwrite the file on disk, instead it poisons the cache with the wrong backing file. After a reboot the file will be back to normal, even if the cache is flushed back to disk (perhaps a privileged process opened the file) I'd expect the new data to be flushed back to the store file not the \u"real\u" file.

Fixing wise, one way you could go would be to always virtualize the file when mapped as a section regardless of the requested access. However I can't be certain there's not another route to this which could be exploited, for example just reading from the file might be sufficient to poison the cache if done at the right time.

These operations can't be done from any sandbox that I know of so it's only a user to system privilege escalation. 

ADDITIONAL NOTE:
As the FILE_OBJECT can't be completely locked across all the file operations the kernel makes use of Auto Boost to lock certain structures such as the SECTION_OBJECT_POINTERS and CONTROL_AREAs. The LUAFV driver doesn't know anything about this so it's possible to get delayed virtualization to complete from another thread in the middle of section creation resulting in mismatched pointers and ultimately a bug check. The easiest way to achieve the bug check is to map a virtualized file as an image with the Microsoft Signed mitigation policy enabled. If the file isn't correctly signed then it will cause the section creation to fail, but after the CONTROL_AREA has been setup. As it's possible to oplock on the kernel opening catalog files the delayed virtualization process can be completed at the right moment resulting in a lock mismatch when tearing down the setup CONTROL_AREA.

I can't really tell if this is exploitable or not (I'm siding with no), but as it's related I thought I should report it to ensure what ever fix for the current issue covers this edge case as well, or at least doesn't make it work. I've provided a kernel crash report \u"additional_crash.txt\u" with this report, and I can provide a PoC if required.

Proof of Concept:

I've provided a PoC as a C# project. It will poison the cache for the file license.rtf in system32 with arbitrary contents. Note it uses a hardlink to virtualize the file, but it doesn't have to as it could open the system32 file itself. It's just done as it was easier to test this way and doesn't impact the exploit. Also note that if the license.rtf file has been opened and the cache manager has created an entry then the exploit fails. In theory this would be deleted eventually (perhaps only under memory pressure), but a quick reboot usually fixes it unless your system opened license.rtf everytime the system starts.

1) Compile the C# project. It'll need to pull NtApiDotNet from NuGet to build.
2) As a normal user run the PoC. 
3) Open the file %WINDIR%\\System32\\license.rtf in notepad to see the contents.

Expected Result:
The license.rtf file contains the original RTF contents.

Observed Result:
The virtualization poisoned the contents of license.rtf with a new text string.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.

```
Found by: forshaw@google.com


### Related CVE Numbers: CVE-2019-0836.


Windows: LUAFV PostLuafvPostReadWrite SECTION_OBJECT_POINTERS Race Condition EoP
Platform: Windows 10 1809 (not tested earlier)
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

Summary:
 

The LUAFV driver has a race condition in the LuafvPostReadWrite callback if delay virtualization has occurred during a read leading to the SECTION_OBJECT_POINTERS value being reset to the underlying file resulting in EoP.

Description:

NOTE: While it has a similar effect as issue 49960 I believe it is a different root cause which might still be exploitable after any fixes. This bug is actually worse than 49960 as you can modify the original file rather than just the cached data and you can do it to any file which can be virtualized as you don't need to have a file which has a NULL CONTROL_AREA pointer.

When a IRP_MJ_READ request is issued to a delay virtualized file the filter driver first calls LuafvPreRedirectWithCallback which determines if the file is virtualized, it then sets the underlying, read-only file as the target file object for the filter processing as well as storing the file object in the completion context. When the read operation completes the LuafvPostReadWrite method is called which will inspect the completion context and copy out the file position and the SECTION_OBJECT_POINTERS value. 

As there's no locking in place at this point if the file delay virtualization is completed between the call to LuafvPreRedirectWithCallback and LuafvPostReadWrite then the SECTION_OBJECT_POINTERS and cache from the read-only file is used to overwrite the top-level \u"fake\u" file object, even though LuafvPerformDelayedVirtualization would have changed them to the new read-write virtual store file. By exploiting this race it's possible to map the \u"real\u" file read-write which allows you to modify the data (you can probably also just write to the underlying file as well).

The trick to exploiting this bug is winning the race. One behavior that makes it an easy race to win is the delayed virtualization process passes on almost all CreateOptions flags to the underlying file create calls. By passing the FILE_COMPLETE_IF_OPLOCKED flag you can bypass waiting for an oplock break on IRP_MJ_CREATE and instead get it to occur on IRP_MJ_READ. The following is a rough overview of the process:

1) Open a file which will be delay virtualized and oplock with READ/HANDLE lease.
2) Open the file again for read/write access which will be delay virtualized. Pass the FILE_COMPLETE_IF_OPLOCKED flag to the create operation. The create operation will return STATUS_OPLOCK_BREAK_IN_PROGRESS but that's a success code so the delayed virtualization setup is successful.
3) Create a new dummy file in the virtual store to prevent the driver copying the original data (which will likely wait for an oplock break).
4) Issue a read request on the virtualized file object, at this point the IRP_MJ_READ will be dispatched to \u"real\u" file and will get stuck waiting for an oplock break inside the NTFS driver.
5) While the read request is in progress issue a IRP_MJ_SET_EA request, this operation is ignored for oplock breaks so will complete, however the LUAFV driver will call LuafvPreWrite to complete the delayed virtualization process.
6) Close the acknowledge the oplock break by closing the file opened in 1. 
7) Wait for read operation to complete.
8) Map the file as a read/write section. The data should be the \u"real\u" file contents not the dummy virtual store contents. Modifying the file will now cause the \u"real\u" file to be modified.

Note that even if you filtered the CreateOptions (as you should IMO) the race still exists, it would just be harder to exploit. Fixing wise, you probably want to check the virtualized object context and determine that the the delay virtualization has already occurred before overwriting anything in the top-level file object.

These operations can't be done from any sandbox that I know of so it's only a user to system privilege escalation. 

Proof of Concept:

I've provided a PoC as a C# project. It will map the license.rtf file as read-write, although it won't try and modify the data. However if you write to the mapped section it will change the original file.

1) Compile the C# project. It'll need to pull NtApiDotNet from NuGet to build.
2) As a normal user run the PoC. 
3) The PoC should print the first 16 characters of the mapped file.

Expected Result:
The mapped data should be all \u2018A' characters.

Observed Result:
The mapped data is the actual license.rtf file and it's mapped writable.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw@google.com

### Related CVE Numbers: CVE-2017-10204.


VirtualBox: COM RPC Interface Code Injection Host EoP
Platform: VirtualBox 6.0.4 r128413 x64 on Windows 10 1809
Class: Elevation of Privilege

Summary:
 

The hardened VirtualBox process on a Windows host doesn't secure its COM interface leading to arbitrary code injection and EoP.

Description:

This issue is similar in scope to others I've reported such as S0867394/CVE-2017-10204. It allows you to call arbitrary code inside the hardened process which can expose the kernel drivers to normal user processes resulting in EoP. I'm assuming that this is still an issue you'd like to fix?

The VirtualBox hardening code allows other processes running as the same user to read all virtual memory by granting the PROCESS_VM_READ access right. It isn't obvious that this could result in arbitrary code execution, except that VirtualBox initializes out-of-process COM and by extension exposes an RPC interface. With access to read arbitrary memory from such a process it's possible to call existing interfaces running inside the VirtualBox process such as the undocumented IRundown interface which COM uses for various infrastructure tasks. This interface has a DoCallback method which will execute an arbitrary function in the process with a single arbitrary pointer sized argument.

You can get more details from my blog about using this technique as a mechanism to bypass Windows Protected Processes, https://googleprojectzero.blogspot.com/2018/11/injecting-code-into-windows-protected.html. In this case we don't need to abuse an old version of WERFault to dump memory as the hardening driver allows us to do just read memory.

To fix this issue you might want to block PROCESS_VM_READ access entirely, it's not clear if this is a necessary access right for something or just because it didn't seem to be dangerous. I'd also call CoInitializeSecurity at process start and pass an security descriptor to the pSecDesc parameter which limits access to administrators and perhaps service accounts. However be careful if you decide to only initialize CoInitializeSecurity as it's process wide and has weird behaviors which might result in the security descriptor getting unset. I'd probably call the API every time you call CoInitialize just in case.

Proof of Concept:

I've provided a PoC as a C# project. It will use the vulnerability to call ExitProcess with the exit code \u201812345678' inside a VirtualBox process. Note that by default it's designed to work out of the box on Windows 10 1809 x64 updated to March 2019. It will fallback to trying to lookup symbol addresses using the DBGHELP library if the combase DLL doesn't match, however you'll need to have cached the symbols for combase inside C:\\ProgramData\\dbg\\sym. You can do this by running the \u2018symchk' tool from a Debugging Tools for Windows installation and passing the path to the x64 version of combase.

1) Compile the C# project using Visual Studio 2017. It'll need to pull NtApiDotNet from NuGet to build.
2) Start a virtual machine and note the PID of the hardened VirtualBox process.
3) As a normal user run the PoC passing the PID of the hardened VirtualBox process.

Expected Result:
The PoC fails to call code inside the target process.

Observed Result:
The PoC executes ExitProcess inside the hardened process and verifies the return code once the process exits.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw@google.com

### Related CVE Numbers: CVE-2019-0881.


Windows: CmKeyBodyRemapToVirtualForEnum Arbitrary Key Enumeration EoP
Platform: Windows 10 1809 (not tested earlier)
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

Summary:
 

The kernel's Registry Virtualization doesn't safely open the real key for a virtualization location leading to enumerating arbitrary keys resulting in EoP.

Description:

When the virtualization flag is set on the primary token certain parts of the HKLM\\Software hive are virtualized to a per-user location under Software\\Classes. If the key exists in HKLM (and can be virtualized) then a handle to the HKLM key is opened read-only and the virtualized key is only created if any modification is made to the key, such as writing a value.

However, if a virtualized key already exists then that key is opened and the real key is only opened on demand. One reason to open the backing key is if the virtual key is enumerated, to provide compatibility the kernel will merge the key/value information from the real key into the virtual key. The real key is opened every time a call is made to NtEnumerateKey, NtQueryValue etc.

The open of the real key is performed in CmKeyBodyRemapToVirtualForEnum. It first constructs the real path to the key using CmpReparseToVirtualPath then opens the key object using ObReferenceObjectByName. The problem here is two fold:
1) The access mode passed to ObReferenceObjectByName is KernelMode which means security checking is disabled.
2) The open operation will follow symbolic links in the registry.

When combined together these two issues allow a normal user to redirect a real key to an arbitrary registry location, as security checking is disabled then it will open any key including the SAM or BCD hives. The only requirement is finding a virtualizable key inside HKLM which is writable by the normal user. There's a number of examples of this, but the easiest and ironic one to exploit is the HKLM\\SOFTWARE\\Microsoft\\DRM key. In order to get the virtualization to work you do need to create a new subkey, without any virtualization flags (the DRM key can be virtualized anyway) with a security descriptor which limits the user to read-only but grants the administrator group full access. This will meet the virtualization criteria, and as the key is in HKLM which is a trusted hive then any symbolic link can reparse to any other hive. This can be exploited as follows:

1) Create a new subkey of DRM which can only be written to by an administrator (just pass an appropriate security descriptor). This should be done with virtualization disabled.
2) Open the new subkey requesting read and write access with virtualization enabled. Write a value to the key to cause it to be virtualized then close it.
3) Reopen the subkey requesting read and write access with virtualization enabled.
4) Replace the new subkey in DRM with a symlink to \\Registry\\Machine\\SAM\\SAM. 
5) Enumerate keys or values of the virtual key, it should result in the SAM hive being opened and enumerated. Repeat the process to dump all data from the hive as needed.

Fixing wise, I'm not really sure why the real key is opened without any access checking as the code should have already checked that the user could open the real key for read-only in order to create the virtual key and if the call fails it doesn't seem to impact the enumeration process, just it doesn't return the data. You might try and block symbolic link reparsing, but passing OBJ_OPEN_LINK isn't sufficient as you could replace a key higher up the key path which is the actual symbolic link.

These operations can't be done from any sandbox that I know of so it's only a user to system privilege escalation. 

Proof of Concept:

I've provided a PoC as a C# project. It will use the vulnerability to enumerate the top level of the SAM hive.

1) Compile the C# project. It'll need to pull NtApiDotNet from NuGet to build.
2) As a normal user run the PoC. 
3) The PoC should print the subkeys of the SAM hive.

Expected Result:
The query operation should fail.

Observed Result:
The SAM hive key is opened and enumerated.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.


Found by: forshaw@google.com

### Related CVE Numbers: CVE-2019-0755.


Windows: CmpAddRemoveContainerToCLFSLog Arbitrary File/Directory Creation EoP
Platform: Windows 10 1809 (not tested earlier)
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

Summary:
 

The kernel's CmpAddRemoveContainerToCLFSLog function doesn't safely create new transaction log containers leading to arbitrary file creation and EoP.

Description:

The configuration manager in the kernel supports creating registry keys within a transaction. To store the transaction log data a CLFS log file is used which is split into multiple containers. These transaction log files are stored within the same directory as the hive files with the names ending BLF. Container files, with the suffix TxR.X.regtrans-ms are created on demand if the amount of transaction data being stored is larger than available log space. 

As these container files are created within the security context of the process creating the transaction this creates a problem as the CLFS driver always creates file with the previous mode set to UserMode. This would mean a non-administrator couldn't create transactions in any hive which is stored in a location they can't write to, which includes any HKLM hive which wouldn't be very useful. To solve this problem before calling ClfsAddLogContainer the kernel code attaches the calling thread to the System process and disables any impersonation token which ensures the call to CLFS will come from the SYSTEM user. 

This becomes an issue for the user's registry hives as those hive files are located in user writable locations. Therefore as the names of the containers are predictable (just using an incrementing counter) it's possible to redirect the container file creation through abusing symbolic links. 

Due to the location of the hive file it'd seem initially difficult to exploit this as a normal user as you can't introduce a NTFS mount point in a parent path as you can't delete/rename the existing hive files while the user is logged in. On newer versions of Windows with Developer Mode enabled you could create NTFS symbolic links but we've got to assume that this setting wouldn't be enabled by default. It turns out looking at the call to IoCreateFileEx in CLFS that it doesn't specify either FILE_DIRECTORY_FILE or FILE_NON_DIRECTORY_FILE which means it's exploitable by abusing mount points as if it were a file level symbolic link (as documented in https://googleprojectzero.blogspot.com/2017/08/windows-exploitation-tricks-arbitrary.html). The file is created with the security descriptor of the original hive/transaction log which means the user can write to the created file.

However this only works until 1803 which fixes this behavior and blocks reparsing from a mount point to a normal file. I've not investigated in depth but based on the flags set in the call in Process Monitor this \u"fix\u" works by setting the FILE_DIRECTORY_FILE in the parse context if a mount point is encountered before the driver returns STATUS_REPARSE. Ironically this behavior works in our favor, as the call is a FILE_CREATE disposition call then the file doesn't exist anyway and by dropping a mount point named appropriately the CLFS code will create an arbitrary directory even though the code didn't originally specify that requirement. Once CLFS realizes it's created a directory (or at least something it can't write to) it tries to back out and deletes the new directory, however if we're quick we can write a file to the new directory (again as the security descriptor grants us access) which makes the delete operation fail. We can then use the directory to get system privileges, such as through abusing the DiagnosticsHub Collector Service.

Funnily enough I think prior to 1803 this would be harder to exploit as the transaction logs seem to be deleted when the user logs out and it wouldn't be possible to modify the contents of the newly created arbitrary file as it only allows read sharing. An unexpected consequence of a security mitigation it seems.

Fixing wise there's at least two things you could do. Firstly the generated name is under control of the kernel and so could be more random to prevent resource planting attacks. You could also modify CLFS to specify explicitly FILE_NON_DIRECTORY_FILE and maybe FILE_OPEN_REPARSE_POINT to prevent abuse of mount points and even symbolic links if the target is an NTFS symbolic link.

Proof of Concept:

I've provided a PoC as a C# project. It will use the vulnerability to create an arbitrary directory (on 1809 at least). Note that you're likely to need at least two CPUs for the exploit to be successful as it requires winning the race between the directory being created and then being deleted. Note that if you get an error stating the transaction log file was full then it failed to capture the directory. Try running the PoC again as it should be possible to run it multiple times without significant consequence (although the transaction functionality of the user's registry _might_ be broken).

1) Compile the C# project. It'll need to pull NtApiDotNet from NuGet to build.
2) As a normal user run the PoC passing the name of a directory to create 
3) The PoC should print the opened directory and granted access.

Expected Result:
The file creation 

Observed Result:
The arbitrary directory was created and is writable by the current user.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.


Found by: forshaw@google.com

### Related CVE Numbers: CVE-2019-0755.


Windows: Windows Font Cache Service Insecure Sections EoP
Platform: Windows 10 1809 (not tested earlier)
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

Summary:
 

The Windows Font Cache Service exposes section objects insecurely to low privileged users resulting in EoP.

Description:

The Windows Font Cache Service is used to speed up the performance of DirectWrite font renderer by caching various pieces of font information in a central location. The cache can then be accessed over a custom ALPC connection. In order to support passing back large data sets, such as the cache, the service makes use of memory mapped files. Rather than sharing the sections using a global name the service opens a handle to the calling process (using NtAlpcOpenSenderProcess) then duplicates the section handle into the caller. When the ALPC call returns the caller can pick up the section handle and map it.

Almost certainly for reasons of security the service doesn't give the caller a section object with SECTION_MAP_WRITE access as it doesn't want the caller to modify the contents of the cached data, only read from it. Therefore when duplicating the handle it only specifies SECTION_MAP_READ which removes the write access from the handle. Unfortunately there's a problem, specifically the section objects are created without a name or a security descriptor. This means there's no security on the object (you can't even set a security descriptor after creation) which means the caller can just call DuplicateHandle again to get back write access on the section handle, map the section as writeable and modify the contents. This behavior was the topic of my first Project Zero blog post (https://googleprojectzero.blogspot.com/2014/10/did-man-with-no-name-feel-insecure.html) where Chrome had a very similar use case and subsequent vulnerability.

How can this be exploited? The cached data has a lot of complex binary data therefore there's likely to be some memory corruption vulnerability here as there's a presumption that only the service could modify the data. That said there does seem to be an enormous number of checks (and checksums) in the code and not being one for fuzzing this is probably a difficult approach. I think the cache also contains file paths, it's possible that this might be modified to read arbitrary files as there's an ALPC call to get a file handle, although this would only run at LOCAL SERVICE so it's not much better than a normal user's access but might be useful from an AppContainer.

Instead of fuzzing the file format I decided to look elsewhere, there's another vulnerable section object which is passed back from a call to AlpcServer::ProcessGetEventBufferMessage which seems to be a simple event log in a circular buffer. The service stores the current write location at offset 0x10 into the mapped section. As we can change the section back to write we can modify the offset, cause a logged event to occur and get a memcpy into an address up to 2GB relative to the start of the mapped log inside the service. As the service doesn't expect this value to be modified by other processes it doesn't do any bounds checks. For example here's a crash when setting the pointer to 0x7FFFFFFF:

(2f40.10a4): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
msvcrt!memcpy+0x1cc:
00007ff8`5dd34a0c 488901          mov     qword ptr [rcx],rax ds:000001ec`931b0043=????????????????

0:002> k
 # Child-SP          RetAddr           Call Site
00 00000055`dbfff818 00007ff8`2a8015e2 msvcrt!memcpy+0x1cc
01 00000055`dbfff820 00007ff8`2a7fb2b9 fntcache!SharedCircularEventSink::LogEvent+0x3d2
02 00000055`dbfffa00 00007ff8`2a7faf24 fntcache!EventLogger::LogGenericEvent+0x89
03 00000055`dbfffa70 00007ff8`2a7fabb6 fntcache!AlpcServer::ProcessCacheHandleRequest+0x84
04 00000055`dbfffb90 00007ff8`2a808c35 fntcache!AlpcServer::ProcessMessage+0x24e
05 00000055`dbfffc30 00007ff8`2a808b17 fntcache!AlpcServer::Run+0x105
06 00000055`dbfffce0 00007ff8`5dc181f4 fntcache!AlpcServer::ThreadProc+0x17
07 00000055`dbfffd30 00007ff8`5f54a251 KERNEL32!BaseThreadInitThunk+0x14
08 00000055`dbfffd60 00000000`00000000 ntdll!RtlUserThreadStart+0x21

0:002> dc @rcx-7FFFFFFF
000001ec`131b0044  6961772c 33300a74 2039302f 343a3332  ,wait.03/09 23:4
000001ec`131b0054  34343a32 3435392e 3530362c 30312c36  2:44.954,6056,10
000001ec`131b0064  38353030 6361432c 74436568 64612c78  0058,CacheCtx,ad
000001ec`131b0074  656c4564 69622c6d 70616d74 2f33300a  dElem,bitmap.03/
000001ec`131b0084  32203930 32343a33 2e34343a 2c343539  09 23:42:44.954,
000001ec`131b0094  30363234 3030312c 2c393030 63706c41  4260,100009,Alpc
000001ec`131b00a4  2c727653 74617473 69682c65 33300a74  Svr,state,hit.03
000001ec`131b00b4  2039302f 343a3332 34343a32 3435392e  /09 23:42:44.954

We can see that RCX is 0x7FFFFFFF above the start of the buffer (the buffer has a 0x44 byte header) and RCX is used at the target of the memcpy call. While we don't fully control the contents of the write it is at least predictable, bounded in size and therefore almost certainly exploitable. At least this is the best I could find without spending my time reverse engineering the cache format for no real benefit. 

The ALPC server is accessible to all users as well as all AppContainers and Edge LPAC. So this bug could potentially be used to escape the sandbox. There are many questions about this code which I can't readily answer, like why use raw ALPC rather than RPC or when not use the handle duplication facility of ALPC to pass the handle back rather than relying on duplication (not that it would have made this behavior any safer of course). 

Fixing wise, there's a few different ways you could go about it. Since Windows 8 all unnamed objects can now enforce a security descriptor as long as it's specified when creating the new object. Specifying a restrictive DACL the caller won't have permission to reduplicate back to a writable object. This won't work on Windows 7 and below (assuming the code goes back that far), you can specify a security descriptor but it'll be ignored. For 7 you can assign a randomly generated name (or add it to an anonymous directory object then release the directory). For file based sections, such as the caches you could create separate section objects which are only marked for read access and duplicate those which should stop a user converting to writable. Finally you could just directly map the sections into the caller using NtMapViewOfSection which takes a process handle.

Proof of Concept:

I've provided a PoC as a C# project. It will query for the event buffer section object over ALPC, duplicate the section object to be writable, modify the current write offset then cause the service to generate a new log entry. This process will result in an OOB memcpy in the service when writing the log entry.

1) Compile the C# project. It'll need to pull NtApiDotNet from NuGet to build.
2) Attach a debugger to the Windows Font Cache Service to see the crash.
3) As a normal user run the PoC.

Expected Result:
The event buffer section object is read-only.

Observed Result:
The event buffer section object can be duplicated back to writable and the event buffer modified leading to an arbitrary memcpy in the context of the service.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.


Found by: forshaw@google.com

### Related CVE Numbers: CVE-2019-1089.


Windows: RPCSS Activation Kernel Security Callback EoP
Platform: Windows 10 1903/1809 (not tested earlier)
Class: Elevation of Privilege
Security Boundary (per Windows Security Service Criteria): User boundary

Summary:
 

The RPCSS Activation Kernel RPC server's security callback can be bypassed resulting in EoP.

Description:

The RPCSS service is split into two components, RPCSS which runs as a low-privileged service account and the DCOM launch service which runs as SYSTEM and is responsible for creating new COM processes. Communication between the two services is over an RPC service named Activation Kernel (actkernel). When RPCSS receives a DCOM activation request it will pass that request on to the actkernel service to create new processes. 

The actkernel RPC service implements various privileged operations, therefore it shouldn't be callable from a normal user account. However the service must know who made the activation request to RPCSS. This is acheived by RPCSS impersonating the activator while making the RPC request to actkernel which means the ALPC port used by actkernel must be accessible by any process capable of activating a DCOM object, including AC and LPAC. To limit the call to only RPCSS the service implements a security callback on the RPC server which checks the caller process ID the RPCSS service, this should block arbitrary users on the system calling the service.

Unfortunately there's a flaw in this design, RPC defaults to caching the results on these security checks and actkernel doesn't disable this feature. What this means is once a call is made to actkernel from RPCSS with a user's token the security result is cached. Now that same user can access actkernel directly as the security callback will not be made and the PID will not be checked. 

The caching is done primarily on the token's modified ID, which doesn't change as often as you'd expect including across ALPC impersonation. As long as the user has made some activation request (such as creating an OOP COM server) then the result is cached and the process can access privileged operations.

Looking at what the service exposes an AC sandbox escape might be the best approach. For example the service exposes PrivGetPsmToken which will set an arbitrary SYSAPPID value to a token and return it to the caller. If done from an AC this token is still an AC token in the original package, but with an arbitrary SYSAPPID set which means that security checks which rely on that value can be bypassed. As the AC sid isn't changed this means it can be impersonated by the caller. This could allow sandbox escape via Browser Broker or Desktop Broker by pretending to be Edge or a side-loaded application.

Fixing wise if performance is acceptable then setting the RPC_IF_SEC_NO_CACHE flag on the interface registration should ensure the security callback is always made. You'd probably want to do a search for similar interfaces on Windows. Actkernel might be special in doing a PID check and allowing arbitrary callers via another route but I can't be sure it's the only one.

Proof of Concept:

I've provided a PoC as a C# project. It will use the vulnerability to get a token with an arbitrary SYSAPPID. It first respawns the PoC as the calculator AC, then gets a token for MicrosoftEdge. It doesn't attempt to escape the sandbox, but I'm confident it'd be possible to achieve.

1) Compile the C# project. It'll need to pull NtApiDotNet from NuGet to build.
2) As a normal user run the PoC. 
3) The PoC should print the subkeys of the SAM hive.

Expected Result:
Accessing the actkernel RPC service should fail with an RPC fault.

Observed Result:
The actkernel RPC service grants access and 

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.



Found by: forshaw@google.com


### Windows: SET_REPARSE_POINT_EX Mount Point Security Feature Bypass
Platform: Windows 10 1903, 1809 (not tested earlier)
Class: Security Feature Bypass

Summary:
 

The NTFS driver supports a new FS control code to set a mount point which the existing sandbox mitigation doesn't support allowing a sandboxed application to set an arbitrary mount point symbolic link.

Description:

After multiple previous attempts the kernel mitigation against adding arbitrary NTFS mount points seems pretty robust. However due to the way it was implemented inside the IO manager in the kernel it is fragile to changes inside the filesystem drivers as the mitigation is only implemented when the FSCTL_SET_REPASE_POINT control code is used.

In this case at some point (based on headers probably RS1) a new FSCTL was added to NTFS, FSCTL_SET_REPARSE_POINT_EX to allow overwriting an existing reparse point without having to first delete it. This FSCTL has a different control code to the old one, therefore issuing it does not trigger the mitigation and an arbitrary mount point can be set from any sandboxed applications. This mount point could then facilitate further attacks, for example https://bugs.chromium.org/p/project-zero/issues/detail?id=1413 is probably now vulnerable again to drop an arbitrary file as the current user.

Fixing wise obviously you'd want to also detect this FSCTL and handle it in the mitigation. You'll probably want to verify the NTFS implementation to check that it's not possible to just change the data without specifying a valid tag when an existing tag is already set as the single optional flag you can specify isn't exactly clear on this. You might also want to find a way of getting visibility on new changes which can affect symbolic link operations, as this is 3rd time this has happened recently (previously NPFS symlinks and global symlinks) that I know of.

Proof of Concept:

I've provided a PoC as a C# project. It will create a temporary directory, drop its token's IL to Low then set that directory to be a mount point to the windows folder which would not normally be allowed.

1) Compile the C# project. It'll need to pull NtApiDotNet from NuGet to build.
2) As a normal user run the PoC. 
3) The PoC should print the set mount point path.

Expected Result:
Setting the mount point should fail with access denied.

Observed Result:
The mount point is set to an arbitrary directory.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.


Related CVE Numbers: CVE-2019-1170.



Found by: forshaw@google.com

### Windows: Insecure CSharedStream Object EoP
Platform: Windows 10 1903 (not tested earlier)
Class: Elevation of Privilege

Summary:
 

The shared stream object implemented in SHCORE is unsafe to be shared across security boundaries, doing so can result in elevation of privilege.

Description:

The SHCORE library implements a number of COM objects including a stream which is designed to be shared between processes, CSharedStream. One exported method which returns such a stream is SHCreateReadOnlySharedMemoryStream which is used to share a read-only stream based on a memory buffer between processes.

In order to share this stream between processes the SHCORE library implements a custom marshaling protocol. When the stream object is passed across a COM interface boundary an inner stream object is standard marshaled and wrapped inside the following custom class:

CLSID : 0e119e63-267a-4030-8c80-5b1972e0a456
Name  : Shared Memory Stream Marshaller

This is a trusted marshaller so should be accessible from AppContainer sandboxes etc. During unmarshal of this object at the other side of the interface call the function CFTMCrossProcClientImpl::_UnwrapStream is called which unmarshals the inner standard reference and some additional data and returns a CSharedStreamProxy object. At this point nothing special happens, however when a call is made to one of the stream's methods, such as Read a call is made to CSharedStreamProxy::_EnsureDelegateStream to complete the unmarshal process, this is where the dangerous operations occur.

To share the stream the code uses a shared memory section object, which was created when the stream was initially created. The process calling methods on the stream object might not have permissions to access the process which created the stream section, so to facilitate duplicating the handle the inner stream implements the IDuplicateHandleProvider interface, which has a single method:

HRESULT DuplicateHandleToProcess(int ProcessId, IHandleDuplicator* handle_duplicator, __int3264* handle);

This method takes a process ID of the target process to duplicate the section handle and an instance of an IHandleDuplicator interface. There's multiple problems here with the implement in SHCORE, CSharedStream::DuplicateHandleToProcess:

First the process ID is not verified in any way, this method will duplicate a copy of the section handle to any process that the hosting process has access to. If this was in a SYSTEM process that'd be almost any process on the system. This isn't that major an issue, although the ability to duplicator a section handle into an arbitrary process is probably not as designed.

Secondly, if CSharedStream::DuplicateHandleToProcess can't open the process by ID and a IHandleDuplicator interface is passed then it'll call that interfaces single method which is as follows:

HRESULT DuplicateGivenHandleFromProcess(int pid, __int3264 input_handle, __int3264 output_handle);

This method will receive the process ID of the hosting process and the handle value for a copy of the section handle. The idea being if the hosting process can duplicate the handle perhaps the process hosting the IHandleDuplicator interface can. If the call is successful CSharedStream::DuplicateHandleToProcess assumes the handle value returns is valid in the process and will try and use it as the shared section handle.

The result of this behavior is as follows:

If a stream is shared from a privileged to an unprivileged process it's possible to get the privileged process to duplicate a handle to any process it has access to.

If a stream is shared from an unprivileged process to a privileged process the reverse will happen, a call will be made to DuplicateGivenHandleFromProcess, the resulting handle will be trusted by the privileged process and will be used as a section handle and be closed afterwards. 

The unprivileged to privileged is probably the more immediately section as it allows you to do two things, close an arbitrary handle in the privileged process and create a stream around an existing, unrelated section handle. Also if you could close the existing section handle, you could use the DuplicateGivenHandleFromProcess to reallocate that handle from a privileged IHandleDuplicator then DuplicateHandleToProcess method then duplicate it to an arbitrary process. Although in this case it'll be restricted to duplicating the handle with SECTION_MAP_READ access unless the original was a writable stream which will also map SECTION_MAP_WRITE. One use case is SECTION_MAP_READ maps to FILE_APPEND_DATA access right, so you use it to leak a writeable file handle and append additional data to the end of the file.

You can convert a privileged to unprivileged into the reverse by calling the CopyTo method on the stream and passing it a \u"fake\u" marshalled object. 

Finally are these objects ever shared across a security boundary? The code was initially discovered being used by Windows.Storage.StorageFolder WinRT class to pass a list of filenames across security boundaries. Basically if you can get a StorageFolder object from a privileged process to a less privileged process (such as from RuntimeBroker to an AppContainer process) you could start an exploit chain. Another place I found it used is the CFileChangeTracker::GetChangesInternal method in search indexer which runs as SYSTEM. The method returns a stream object created by SHCreateReadOnlySharedMemoryStream, although it might require configuration changes to get it to return the object.


CSharedSection is not the only implementer of this pattern, SHCORE also contains CGenericFileHandle and COplockFileHandle, but I haven't worked out if you can easily get them across a boundary.

Proof of Concept:

I've provided a PoC as a C# project. It simulates passing a StorageFolder object from a privileged process to a AppContainer sandbox process then attempts to exploit the stream. The AC process unmarshals the StorageFolder object, then does a query to capture a shared stream object. With that object it uses the interfaces to close an existing handle in the privileged process (the handle value is passed on the command line to simplify the exploit) then duplicates a copy of a process handle over the existing handle value. The privileged process prints the NT handle type before and after the AC process execution.

It might have been possible to use Windows.Storage.StorageFolderStaticsBrokered class to get a StorageFolder object which is Partial Trust and would run in a broker, however there was difficulty it getting this to work in a \u"fake\u" AppContainer without the token's package security attribute and getting the exploit code to work inside a \u"real\u" packages application is too much hassle.

1) Compile the C# project. It'll need to pull NtApiDotNet from NuGet to build.
2) As a normal user run the PoC. 
3) The PoC should print the object type of an event handle before and after the AC process.

Expected Result:
The PoC prints that the handle type before and after running the AC process as being an Event.

Observed Result:
The PoC prints the before handle type as Event but the after handle type as Process.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.




Found by: forshaw@google.com

### Intel: ShaderCache Arbitrary File Creation EoP

Intel: ShaderCache Arbitrary File Creation EoP
Platform: Intel Driver 25.20.100.6472, Tested on Windows 10 1909 x64.
Class: Elevation of Privilege

Summary:

The shared shader cache directory can be exploited to create an arbitrary file on the file system leading to elevation of privilege.

Description:

NOTE: I've only tried this on driver 25.20.100.6472, however I couldn't find a newer one and Windows Update on the machine didn't update past this version so I'm assuming it's probably the latest 25.X branch.

The Intel driver has a shared shader cache directory under C:\\ProgramData\\Intel\\ShaderCache. This is presumably used to store pre-compiled shaders to improve performance. The directory is shared by all users on the system and the directory and all files are automatically assigned access control to allow Guests, Anonymous, Authenticated Users and Administrators full access. This access controls setting is very weak, and due to the shared use it possible to modify the directory and files to elevate privileges.

One immediate problem is as far as I can tell the names of the cache files are just EXENAME_1 with no randomization or separation. It's not clear what the \u20181' suffix represents, I assumed it might be the session ID but it doesn't seem to be, and even if it was it doesn't provide any real security.

The first step to exploitation is to find a privileged application which initializes the driver which will cause the cache file to be created. On my test system (a Gen 1 MS Surface Laptop) a good candidate is the UAC consent application. This is useful as it runs as the highest privilege SYSTEM user and it doesn't run all the time so doesn't lock the file for very long. A quick attack which would just corrupt the contents of an arbitrary file is to hardlink the file \u2018consent_1' to a system file and start a UAC elevation. The user doesn't have to accept the elevation (and this also works for a non-admin user as well), it just has to display the UI to write the cache file and corrupt a system file.

A more useful privilege escalation requires a bit more work. You can replace the ShaderCache directory with a directory mount point which redirects all write requests to an arbitrary directory on the system. If the mount point is set then you can write an arbitrary file to, for example, the system32 directory, as the access control on the new file allows the user to modify it we can then write a DLL to the file and use that to elevate privileges. 

The only thing standing in your way to exploit this is you can't set a mount point if the directory has any files, and a few applications (such as DWM) hold a read lock on the files which prevent them being deleted. However we can get around this if we're willing to require a reboot using the following process:

1. Apply a DACL to the ShaderCache directory which only allows full read access and write attributes access to the contents of the directory for all users. We can do this as we've been granted full control over the directory. By applying this DACL no new applications can create files in the ShaderCache directory, however as we've got write attributes access we can set a mount point at a later time. The driver code won't try and fix the DACL if it doesn't allow writing.
2. Enumerate the directory and try and delete each file. If a file can't be deleted then set the DACL to only allow delete access for all users, which we can do as again we have full access. This prevents an application opening for either read or write access, but will allow us to delete the file afterwards.
3. If the directory is not empty force a reboot of the system, when the system has rebooted re-run the exploit which should now be able to delete the previously locked files as the applications will have been blocked from opening them.
4. With an empty directory the mount point can now be set to point all file writes to an arbitrary directory.
5. Start a UAC elevated application which will start consent.exe which should try and create the file consent_1 in the ShaderCache directory. This creation will be redirected to the arbitrary location as the SYSTEM user which basically grants access to almost anywhere on the filesystem. As the file also has the access control set then once consent.exe has closed and released the lock the file can be opened for write access and its contents rewritten. It's possible to also change the name of consent_1 to something else if necessary.

There are various things which would help in fixing this:
* The SharedCache directory shouldn't be shared between users, a per-user location with appropriate ACLs should be a minimum.
* Explicit access control shouldn't be added during file creation. File creation should rely on ACL inheritance from the parent directory (which is already set but not used). If inheritance was used then the arbitrary file creation, which would still exist would not be controllable by the attacker and at best would be a DoS data corruption attack. I'd also recommend removing explicit ACEs for anything but admin and use the CREATOR OWNER SID to automatically assign access to only the creator of the file.
*The shader cache probably shouldn't be initialized in privileged scenarios such as system services, although DWM is probably a valid use case which should be taken into account.
* As there might be cases where multiple users could write to the same cache directory (such as UAC elevated applications) the file names should use some sort of differentiator, perhaps the user's SID and integrity level (or admin status).

Ideally only users of the same privilege should be able to write to these cache files. The data contained in the files is being parsed by native code which could have security issues, so just being able to modify file contents between privilege levels is a security risk even if the mount point issue is remediated.

Proof of Concept:

I've provided a PoC as a C# project. This PoC follows the process outlined earlier. A reboot will probably be required during the process to unlock the files, it might be possible to find a way around this but I'm only demonstrating the issue. The result of the exploit should be the file c:\\windows\  est.txt being created with arbitrary contents which should not normally be possible. A UAC elevation prompt should be visible during exploitation, there's no need to click on anything. However if the prompt doesn't show the exploit probably won't work.

NOTE: As mentioned this was tested on driver version 25.20.100.6472 running on an up to date Windows 10 1909 x64.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to build.
2) Run the PoC executable.
3) If requested reboot the machine. Once rebooted log back in and rerun the PoC.
4) A UAC elevation prompt should show briefly, do not click on it and wait for it to automatically end.
5) Console should print that it successfully wrote to the test file.

Expected Result:
Can't modify ShaderCache.

Observed Result:
The ShaderCache is modified to redirect file writes and an arbitrary file test.txt is created in the Windows folder.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse or a patch has been made broadly available (whichever is earlier), the bug report will become visible to the public.


Related CVE Numbers: CVE-2020-0516/INTEL-SA-00315inFebruary,CVE-2020-0516.



Found by: forshaw@google.com

### Windows: NtFilterToken ParentTokenId Incorrect Setting EoP

Windows: NtFilterToken ParentTokenId Incorrect Setting EoP
Platform: Windows 10 1809, 1903 and 1909
Class: Elevation of Privilege
Security Boundary: User

Summary:
 Starting in 1903 the setting of the ParentTokenId field of a filtered token is incorrect leading to potential sandbox escape and EoP.

Description:

I don't know if this change was intentional, however it's at least a change from earlier behaviors.

Prior to Windows 10 1903 when a restricted token is created the new token's ParentTokenId field is set to the TokenId field of the token creating it. When the new token is assigned to the process during creation if the caller does not have SeAssignPrimaryTokenPrivilege then the kernel will check if the token is either a child or a sibling of the current process token. If the new token fails both checks then the token is not allowed to be assigned. 

Normal token assignment succeeds because of the sibling relationship. Whereas restricted tokens succeed because of the child relationship, but only if the primary token of the process creating the new process was used to create the restricted token. This has a security benefit for sandboxes such as those based on Chromium as the only way to create a new process with a less restricted token would be to open the original parent token and create a new restricted token from that. This attack mitigated in Chromium in two ways:

1. The primary token of the broker can't be opened directly by a sandbox process due to mandatory IL policy hardening (see HardenProcessIntegrityLevelPolicy).
2. NTOS has an RtlIsSandboxToken check which prevents creating a new restricted token which is less restrictive than the original.

However, in 1903 and 1909 the NtFilterToken behavior has changed. Instead of setting ParentTokenId to the TokenId of the base token, it instead copies the ParentTokenId field from the base token. The result is the child token assignment check no longer matches and instead the sibling check matches. This means that a sandboxed process only needs any Token from the same user rather than the original primary token which it was created with to spawn a new process making 1 redundant. And as we can assign any token we like we don't need to call NtFilterToken so the sandbox mitigation 2 doesn't come into play.

There are caveats to this. Firstly you still can only create a process with an IL <= to the current IL. But an unsandboxed token at Low IL gives much more leverage to escape the sandbox than a restricted token at Low IL. You also need to be able to get to a token, this is easy for the Chromium GPU process but not from a renderer.

The only reason this can't be directly used as a GPU Process sandbox escape is due to the use of a Job object which only allows one process at a time. On Windows 10 the GPU process also has child process mitigation enabled but that's circumvented if you get a token.

Fixing wise it should be sufficient to correct the setting of ParentTokenId back to the parent's Token ID. I could easily imagine this was highlighted during checking or refactoring and it didn't seem to make sense so it was \u"fixed\u".

It should be noted that there's an additional sandbox check in NtDuplicateToken to prevent converting a read-only unrestricted token to a writable one which would be needed to drop IL. However the logic is flawed, it limits the granted access to RX but the DACL of the token is based on the default DACL of the caller. Therefore once you get back the token handle with RX access it can be reduplicated back to a full access handle again. Perhaps you might want to check what the original intent of this check was and fix it?

Proof of Concept:

I've provided a PoC as a C# project. It only demonstrates the issue of the ParentTokenId. It shouldn't be considered representative of an actual attack. If you run the PoC on 1809  it should fail to create the third process, but on 1903 and 1909 it should succeed.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Run the PoC as a normal user.

Expected Result:
The creation of the third process should fail with STATUS_PRIVILEGE_NOT_HELD.

Observed Result:
The creation of the third process succeeds as an unrestricted low IL process.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse,
the bug report will become visible to the public. The scheduled disclosure
date is 2020-04-29. Disclosure at an earlier date is also possible if
agreed upon by all parties.


Related CVE Numbers: CVE-2020-0981.



Found by: forshaw@google.com

### Windows: SE_SERVER_SECURITY Security Descriptor Owner EoP

Windows: SE_SERVER_SECURITY Security Descriptor Owner EoP
Platform: Windows 10 1903/1909 (not checked earlier)
Class: Elevation of Privilege
Security Boundary: User

Summary:
 By using the poorly documented SE_SERVER_SECURITY Control flag it's possible to set an owner different to the caller, bypassing security checks.

Description:

When an object's security descriptor is assigned with the poorly documented SE_SERVER_SECURITY control flag set the kernel will replace all Allow ACEs with Compound ACEs but it will also use the Primary Token when checking the owner SID rather than the effective token. This is done in the following code where Server indicates the SE_SERVER_SECURITY flag was set:

BOOLEAN SepValidOwnerSubjectContext(PSECURITY_SUBJECT_CONTEXT SubjectContext, 
                                   PSID OwnerSid, BOOLEAN Server) {
  PTOKEN Token = SubjectContext->ClientToken;
  if (Server || !Token)
    Token = SubjectContext->PrimaryToken;
  
  ...
}

If the Primary Token is different to the impersonated caller then this allows the caller to set any allowed group SID for that primary token rather than their own. A simple example is the SMB server, all requests run on a server thread as SYSTEM while impersonating the caller. If you set the SE_SERVER_SECURITY Control flag then the caller can set either the SYSTEM SID or BUILTIN\\Administrators SID which the caller should not be allowed to do.

Is this useful? Almost certainly there's some applications out there which use the Owner as an indicator that only an administrator could have created the file (even if that's not a very good security check). For example VirtualBox uses it as part of its security checks for whether a DLL is allowed to be loaded in process so I could imagine other examples including Microsoft products. 

This is a similar bug in concept to MSRC Case 41795. It's more limited in one way, in that you can only set a specific range of owners instead of any owner. However, it's more flexible in that it applies to not just new files but also existing files.

Note that the bug is not really in the SMB server. Any other service, such as RPC or COM which takes an arbitrary binary Security Descriptor and writes to a resource under impersonation is likely exploitable depending on the primary token used by the service. However one way of fixing this would be to have checks in SMB for this flag (and maybe SE_DACL_UNTRUSTED) which should really be used but it's possible other services might be affected.

Proof of Concept:

I've provided a PoC as a C# project. It will create the file %USERPROFILE%\  est.txt via SMB with the SYSTEM SID as the owner.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Run the PoC as a normal user.

Expected Result:
Setting SYSTEM SID as the owner returns STATUS_INVALID_OWNER.

Observed Result:
SYSTEM SID is successfully set as the owner.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse,
the bug report will become visible to the public. The scheduled disclosure
date is 2020-04-29. Disclosure at an earlier date is also possible if
agreed upon by all parties.





Found by: forshaw@google.com

### Firefox: Default Content Process DACL Sandbox Escape

Firefox: Default Content Process DACL Sandbox Escape
Platform: Firefox 73.0.1 and 75.0a1, 64-bit on Windows 10 1809/1909 (not tested earlier OS versions).
Class: Elevation of Privilege

Summary:
 The Firefox content processes do not sufficiently lockdown access control which can result in a sandbox escape.

Description:

According to https://wiki.mozilla.org/Security/Sandbox the current content process sandbox is Level 5 which runs with Chromium token level of USER_LIMITED. However, USER_LIMITED is sufficient to open any of the other content processes running at the same time.

The ability to open another process presents a problem, the initial token is set to USER_RESTRICTED_SAME_ACCESS. If a content process is compromised via an RCE then an attack waits for a new content process to be created (there's also likely a way of making a new content process start programmatically) the process can be opened before the initial thread token is dropped with the call to LowerToken and the attack can run as USER_RESTRICTED_SAME_ACCESS. 

Even though the content process runs as a Low Integrity Level this access is sufficient to escape the sandbox. There's likely to be multiple routes to escape but one which works that I've provided as a POC is as follows:

1. Wait for a new content process to start. Immediately suspend the process.
2. Impersonate the main thread's initial token to elevate privileges.
3. Create an out-of-process COM server using the privileged identity to escape the process Job object. This also bypasses the child process mitigation as that's set on the primary token, not the impersonation token.
4. Migrate to the new COM server process, abuse a UAC \u"feature\u" documented at https://www.tiraniddo.dev/2019/02/accessing-access-tokens-for-uiaccess.html which allows us to create a new process with UI Access privilege under our control.
5. Use UI Access to bypass UIPI and programmatically access the Explorer Run Dialog to spawn a process outside of the sandbox.

Fixing wise, you should be able to call the Chromium sandbox target policy function SetLockdownDefaultDacl to restrict the access between content processes. Note that it's possible this will cause some system code to fail, you'll need to do extensive testing to make sure it's not a problem. 

On a related topic I'd also recommend calling:
sandbox::ApplyProcessMitigationsToCurrentProcess(sandbox::MITIGATION_HARDEN_TOKEN_IL_POLICY).

In the main browser process. This prevents related token stealing attacks, which while mostly mitigated in Windows could still pose a risk. This can be done in slow time, it doesn't have to be part of this fix.

Proof of Concept:

I've provided a PoC as a Visual Studio 2019 project. It contains a C# injector and a C++ DLL which will be injected into a running copy of Firefox. The exploit will should details to the debug output which you can capture using Sysinternals Debug View.

Note, I've tested this on the latest stable as well as Nightly. It seems at least Nightly it hits a release assert at https://dxr.mozilla.org/mozilla-central/source/ipc/glue/Transport_win.h#68 if debugging, continuing the execution the exploit still works. I think this assert probably due to the process suspension, though it's not entirely clear. I'm of the opinion that it doesn't block the exploit, and is not really related.

1) Compile the VS2019 solution project as Release build, x64. The C# It will need to grab the NtApiDotNet library from NuGet to work.
2) Copy the DLL from x64\\Release and InjectDll.exe and NtApiDotNet.dll from InjectDll\\bin\\Release to a generally accessible directory (say C:\\Test).
3) Start a copy of Firefox running.
4) From a command line run InjectDll.exe FirefoxSandboxEscape.dll. Check that prints a PID, this is the process the code has injected into which should be a sandboxed content process.
5) In firefox create a new tab and navigate to a new web page. This should cause a new content process to be created for the exploit to hijack.

Expected Result:
Code running in one content process should not be able to open other content processes.

Observed Result:
Content process is opened, initial thread token repurposes and sandbox escaped.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse,
the bug report will become visible to the public. The scheduled disclosure
date is 2020-05-28. Disclosure at an earlier date is also possible if
agreed upon by all parties.


Related CVE Numbers: CVE-2020-12388.



Found by: forshaw@google.com

### Windows: AppContainer Enterprise Authentication Capability Bypass

Windows: AppContainer Enterprise Authentication Capability Bypass
Platform: Windows 10 1909
Class: Elevation of Privilege
Security Boundary: AppContainer

Summary:
 
LSASS doesn't correctly enforce the Enterprise Authentication Capability which allows any AppContainer to perform network authentication with the user's credentials.

Description:
One of the original legacy AppContainer capabilities grants access to Enterprise Authentication, which basically means access to the SSPI functions. This is listed on https://docs.microsoft.com/en-us/windows/uwp/packaging/app-capability-declarations as a Restricted Capability which means that it wouldn't automatically be approved in the Windows Store and is probably only used in side-loaded Enterprise LOB applications. Without this capability access to SSPI would be blocked.

If you look at the page on UWP networking (https://docs.microsoft.com/en-us/windows/uwp/networking/networking-basics) it is mentioned that there is an exception if the application is authenticating to a network proxy however it doesn't explain what that means. Digging into LSASRV we find the following code:

BOOL allowed = FALSE;

if ((ClientInfoFlags & FLAG_IS_APP_CONTAINER) == 0) {
  allowed = TRUE;
} else if(context->TargetNameProvided) {
  if (ClientInfoFlags & FLAG_HAS_ENTERPRISE_CAP) {
      allowed = TRUE;
  } else if (LsapIsTargetProxy(context->TargetName)) {
      allowed = TRUE;
  } else {
      ClientInfoFlags |= FLAG_INVALID_PROXY;
      allowed = TRUE;
  }
}

if (!allowed) {
  return SEC_E_INVALID_HANDLE;
}

This code first checks if the caller is in an App Container, if not then it doesn't need to do anything and allows the authentication call to continue. It then checks if the pszTargetName parameter was specified in the call to InitializeSecurityContext. The key is the call to LsapIsTargetProxy which takes the target name, splits it up to get the network address and calls the Firewall API FWIsTargetAProxy to check if the network name matches a currently registered proxy. The only way to be on this list and to return true seems to be if the proxy is set system wide or the proxy comes from an auto detected PAC file, not one manually accessed through WinHttpGetProxyForUrl (that I can tell anyway).

If the target is a proxy then the authentication process is allowed, even if the Enterprise Auth Cap is not specified. The issue is, even if LsapIsTargetProxy returns false the authentication is still allowed to proceed but an additional flag is set to indicate this state. I couldn't find any code which checked this flag, although it's a bit unclear as it comes from a TLS block so tracking down usage is awkward.

What this means is that an AppContainer can perform Network Authentication as long as it specifies a valid target name to InitializeSecurityContext, it doesn't matter if the network address is a registered proxy or not. This is probably not by design, but then this behavior only warrants a few throw away comments with no in depth detail on how it's supposed to behave, maybe it is by design.

The result, as you can specify any Target Name you like you could authenticate to a network facing resource as long as the Application has network access capabilities which aren't really restricted. Also as you can specify any target name, and you're doing the actual authentication then server protections such as SPN checking and SMB Signing are moot.

If you're \"running\" inside Classic Edge you could also use this to access localhost services due to the backdoor in the Firewall APIs. Although there are some caveats. First you have to negotiate a network session otherwise you'll end up with the AppContainer token on the other side which prevents access to the admin shares. Also it seems that on the local machine the negotiated token is a normal user token but running at Low IL. Doesn't mean you couldn't find a system service which would allow escape but it'd be more difficult. Remotely this isn't a problem, the network authenticated token gets the IL appropriate for the authenticated user.

A further warning on the check itself. Even if the code correctly handled the network address not being a proxy the check is wrong. The code calls DsCrackSpn2 to break apart the target name into its components, in this case LsapIsTargetProxy uses the Service Name value. However, let's recall the SPN syntax.

Service Class/Instance:port/Service Name.

The Service Name is actually the service on the host, e.g. if you pass CIFS/127.0.0.1/ABC as the target name then LSASS will check if ABC is a valid proxy and not 127.0.0.1 which represents the network address. The confusion presumably is because if you specify CIFS/127.0.0.1 then DsCrackSpn2 will set both Service Name and the Instance Name to 127.0.0.1. Assuming there is at least one proxy registered you can pass the check by specifying CIFS/targethost/proxyhost. However, it seems that SMB only verifies the Service Class and Instance Name, so you can use this target name, the proxyhost component will pass the LSASS check and then will be ignored by SMB to pass its SPN check.

You should also be verifying the Service Class is HTTP (or whatever it needs to be) as otherwise you could access any service class on the same host as the proxy server.

Proof of Concept:

I've provided a PoC as a C# project. It contains a slightly modified version of Tal Aloni awesome C# SMBLibrary project (https://github.com/TalAloni/SMBLibrary) which adds NTLM Integrated Authentication to the SMBClient class. It'll connect to the local SMB server and list the network shares which shouldn't be something the AC can do.

The POC connects to localhost by default which is blocked from the Calculator AC I am using. To get it to work you need to add the calculator AC to the loopback exemption using the following in an Admin command prompt. Note, this doesn't seem to change the Enterprise Auth behavior.

CheckNetIsolation.exe loopbackexempt -a -n=microsoft.windowscalculator_8wekyb3d8bbwe

You can also test against a remote server without adding this exemption by adding the command line options.

IPAddress CIFS/hostname

The first parameter must be an IP Address of the SMB server the user can authenticate to. The second parameter needs to specify the correct SPN for the target, assuming that SMB SPN verification is enabled.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Run the POC.

Expected Result:
Accessing the SMB server and listing shares should fail

Observed Result:
The local shares are listed.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse,
the bug report will become visible to the public. The scheduled disclosure
date is 2020-08-03. Disclosure at an earlier date is also possible if
agreed upon by all parties.


Related CVE Numbers: CVE-2020-1509.



Found by: forshaw@google.com

### Windows: CmpDoReDoCreateKey Arbitrary Registry Key Creation EoP

Windows: CmpDoReDoCreateKey Arbitrary Registry Key Creation EoP
Platform: Windows 10 2004, 1909
Class: Elevation of Privilege
Security Boundary: Kernel

Summary:
 The handling of KTM logs doesn't limit Registry Key operations to the loading hive leading to elevation of privilege.

Description: If a registry hive isn't cleanly unmounted the kernel will try and recover to a known state this includes any transactions in the normal .LOG files as well any committed but not merged transactions from the KTM log.

The recovery code will call ClfsReadLogRecord/ClfsReadNextLogRecord to get each uncommitted KTM record and process it. Each record has a type, such as Create Key, Set Value or Delete Key. The Log stores the full path to the Registry Key to recreate, not just a hive relative path. As no further checking takes place on the path this means that the Log can target keys which are in a completely different hive to the one being loaded. As this code runs with kernel privileges all security checks are also bypassed. 

The recovery code does first open a base key using the function CmpDoReOpenTransKey which sets the Key's Unit of Work GUID. This seems in theory to block most of the records for succeeding as while the key can be opened when it tries to set the value or similar it fails as unless the hive being targeted is the correct one the transaction isn't associated and the operation fails.

However, there's one exception to this, the CmpDoReDoCreateKey record. This creates an arbitrary key with a specified Security Descriptor. In theory this still fails, however it doesn't take into account registry key symbolic links. By placing a link as the key to create which targets a key which doesn't exist then CmpDoReOpenTransKey opens the parent key, then uses ZwCreateKey to create the final key, as this gets redirected to a completely unrelated registry key which isn't part of the transaction the operation succeeds. 

As the key can also have an arbitrary Security Descriptor it can be used to create a key anywhere and the user can access it afterwards. Of course you can't set a symbolic link from a user hive to a system hive, however you can find a writable key in HKLM (such as HKLM\\Software\\Microsoft\\DRM) where a link can be placed. For example you can exploit this vulnerability with the following process.

1) Create a symbolic link called HKLM\\Software\\Microsoft\\DRM\\LINK pointing to HKLM\\System\\CurrentControlSet\\Services\\ABC.
2) Create the Create Key record pointing at HKLM\\Software\\Microsoft\\DRM\\LINK with a suitable security descriptor.
3) Get KTM log processed, this will open HKLM\\Software\\Microsoft\\DRM and mark in a transaction, then will call ZwCreateKey for LINK which will really create HKLM\\System\\CurrentControlSet\\Services\\ABC.

It's possible that setting a NULL GUID for the transaction might also work, but I didn't test that.

The KTM log will only be read in during NtLoadKey system calls and is disabled for things like Desktop Bridge and User Hives. That doesn't mean it's still not exploitable. The best entry point is to modify a user's NTUSER.dat profile. The problem with this approach is the NTUSER.dat files are locked during normal user operation so they can't be modified. 

However, there also exists the Managed Profile which is stored in NTUSER.man in the user's profile directory. This is used in preference to NTUSER.dat if it's present when the Profile Service loads the users' profile. Therefore a user can add the necessary files with the NTUSER.man prefix instead. If the user logs out then back in again the Managed Profile will be loaded instead and will load the KTM log file which can be used to exploit the vulnerability.

Reading the documentation around the Managed Profile it implies it's supposed to be readonly, why then it sets up the KTM is unclear. Perhaps it's read-only in the sense that it'll be overwritten each time a user authenticates to the system?

From a fixing perspective, would it be possible to verify that the registry path in the log record is actually for the loading hive, or maybe just store relative paths? Also DO NOT just fix the Managed Profile entry point like I know you'll try to do as there are almost certainly other ways this could be exploited such as a domain user with two accounts.

Proof of Concept:

I've provided a PoC as a C# project. It copies some registry files to the user's profile and generates a KTM log which will be loaded when the user logs on again and creates an arbitrary registry key.. Note that once the PoC runs the profile will be corrupt and the user can no longer authenticate as it'll be stuck at the \u"Hi\u" welcome page. You'll need to use another account to verify the registry key got created.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Copy the PoC as well as all associated files in the output directory to a machine to test. It's best not to run this on a machine you care about.
3) Run the poc. It should copy the NTUSER.man files to the user's profile.
4) Logout the current user, then log back in again. Note that due to some sort of auto-logon process it's possible that if you log out or reboot the registry hive will be loaded without even supplying a password.
5) Login with another account and check the key.

Expected Result:
The user profile is corrupted.

Observed Result:
The registry key HKLM\\System\\CurrentControlSet\\Services\\ABC is created with an SD which grants Everyone full access.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse,
the bug report will become visible to the public. The scheduled disclosure
date is 2020-08-13. Disclosure at an earlier date is also possible if
agreed upon by all parties.


Related CVE Numbers: CVE-2020-1377.



Found by: forshaw@google.com

### Windows: CmpDoReadTxRBigLogRecord Memory Corruption EoP

Windows: CmpDoReadTxRBigLogRecord Memory Corruption EoP
Platform: Windows 10 2004, 1909
Class: Elevation of Privilege
Security Boundary: Kernel

Summary:
 The handling of KTM logs when initializing a Registry Hive contains no bounds checks which results in EoP.

Description: If a registry hive isn't cleanly unmounted the kernel will try and recover to a known state this includes any transactions in the normal .LOG files as well any committed but not merged transactions from the KTM log.

The recovery code will call ClfsReadLogRecord/ClfsReadNextLogRecord to get each uncommitted KTM record and process it. Even though these APIs return a size parameter for the log record nothing uses it in the code. Each record also contains other size parameters and again nothing verifies those stay within the bounds of the returned record or even if they make any sense.

It's fairly trivial to make this into out-of-bounds read, though getting back anything useful would be difficult. However there's a trivial out-of-bounds pool memcpy with fully controllable size and content in CmpDoReadTxRBigLogRecord which could be used to corrupt memory and elevate privileges. The code looks roughly like the following:

NTSTATUS CmpDoReadTxRBigLogRecord(PVOID pvReadContext, PKEY_TX Entry) {
  PVOID ret = ExAllocatePoolWithTag(PagedPool, Entry->TotalSize, '  MC');
  DWORD index = 0;
  while ((Entry->type & 0x80000000) && Entry->Data.Index == index)
  {
    memcpy(ret, &Entry->Data.BlockStart, Entry->Data.BlockSize);
    index++;
    ret += Entry->Data.BlockSize;
    // ...
  }
}

If the Log Record's type has the top bit set then it's assumed it's a big log record and so spans multiple smaller records in the log file. First the code allocates a buffer with the TotalSize parameter. As this value is not checked this can be set to 0, or 1 or some other equally small value. The while loop then memcpys from the log record at a fixed offset with a totally different size value. Of course this second size value is also not checked. The end result is trivial memory corruption. Full exploitation is left as an exercise for the reader.

Personally I don't know how any of this code passed even a cursory code review. Perhaps because it only activates in a very specific set of circumstances it's never ended up on the sharp end of a fuzzer? I've not gone back to see how old this code is, as the KTM was added in Vista (and almost immediately deprecated) it's very possible it's of that vintage. It's also possible that someone has rationalized this terrible code on the basis that only Administrators could ever get it to activate so therefore it doesn't need fixing which is demonstrably false. This bug is a good reminder of why supporting Admin to Kernel as a security boundary would be a good thing as it ensures areas of attack surface are covered which would otherwise be ignored.

The KTM log will only be read in during NtLoadKey system calls and is disabled for things like Desktop Bridge and User Hives. That doesn't mean it's still not exploitable. The best entry point is to modify a user's NTUSER.dat profile. The problem with this approach is the NTUSER.dat files are locked during normal user operation so they can't be modified. 

However, there also exists the Managed Profile which is stored in NTUSER.man in the user's profile directory. This is used in preference to NTUSER.dat if it's present when the Profile Service loads the users' profile. Therefore a user can add the necessary files with the NTUSER.man prefix instead. If the user logs out then back in again the Managed Profile will be loaded instead and will load the KTM log file which can be used to exploit the vulnerability.

Reading the documentation around the Managed Profile it implies it's supposed to be readonly, why then it sets up the KTM is unclear. Perhaps it's read-only in the sense that it'll be overwritten each time a user authenticates to the system?

From a fixing perspective, perhaps some bounds checks wouldn't go amiss? Also DO NOT just fix the Managed Profile entry point like I know you'll try to do as there are almost certainly other ways this could be exploited such as a domain user with two accounts.

Proof of Concept:

I've provided a PoC as a C# project. It copies some registry files to the user's profile and generates a KTM log which will be loaded when the user logs on again and causes a memcpy for an oversized value. I've attached to the bug report an example crash as well. Note that once the PoC runs the profile will be corrupt and the user can no longer authenticate as it'll be stuck at the \u"Hi\u" welcome page. That said it should have blue screened before you get there.

1) Compile the C# project..
2) Copy the PoC as well as all associated files in the output directory to a machine to test. It's best not to run this on a machine you care about.
3) Run the poc. It should copy the NTUSER.man files to the user's profile.
4) Logout the current user, then log back in again.  Note that due to some sort of auto-logon process it's possible that if you log out or reboot the registry hive will be loaded without even supplying a password.

Expected Result:
The user profile is corrupted but the system doesn't crash.

Observed Result:
The system crashes with an out-of-bounds memory write.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse,
the bug report will become visible to the public. The scheduled disclosure
date is 2020-08-13. Disclosure at an earlier date is also possible if
agreed upon by all parties.


Related CVE Numbers: CVE-2020-1378.



Found by: forshaw@google.com

### Windows: CloudExperienceHostBroker Unsafe COM Object EoP

Windows: CloudExperienceHostBroker Unsafe COM Object EoP
Platform: Windows 10 1909, 2004
Class: Elevation of Privilege
Security Boundary: User

Summary: The CloundExperienceHostBroker hosts unsafe COM objects accessible to a normal user leading to elevation of privilege.

Description:

On a default install of Windows 10 there’s a scheduled task, \Microsoft\Windows\CloudExperienceHost\CreateObjectTask which creates a SYSTEM process hosting the COM class “CloudExperienceHost Create System Object Server / f7fa3149-91e7-43b7-8040-b707688ced1a”. This is a generic COM broker to serve classes running at SYSTEM to users for the purposes of configuring things like OOBE and the Retail Demo. 

In itself this wouldn’t be an issue as long as the scheduled task and COM servers are appropriately ACL’ed. Unfortunately they’re not. The scheduled task can be started by a normal user, and the COM server (f7fa3149-91e7-43b7-8040-b707688ced1a) doesn’t specify a restrictive Launch Permission in its AppID (f7fa3149-91e7-43b7-8040-b707688ced1a) so the default is used which grants the INTERACTIVE group access. 

Normally while INTERACTIVE would be able to create a new instance the default Access Permissions would only grant Administrators and the SELF SID (which would be SYSTEM) access. However, whether a bug or by design when the CloundExperienceHostBroker process calls CoInitializeSecurity it uses a different AppID (efe2d6d8-a81b-41e7-ae77-e5244ab80522) which grants INTERACTIVE access as well. The end result is a normal unprivileged user can  launch the COM server through the Scheduled Task, activate a new instance and access the resulting COM server.

Again this wouldn’t be a problem as long as the COM server doesn’t do anything dangerous. The COM server vends the generic ICreateObject interface which allows a user to pass a CLSID to create. The broker will only create classes which are registered in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudExperienceHost\Broker\ElevatedClsids which is the following on Windows 10 1909.

0316bbc2-92d9-4e2e-8345-3609c6b5c167 CloudExperienceHost Diagnostics Elevated Manager
06dc6740-fd0d-426a-9bf6-20ddbd7d53ce 
0b26fe8c-9e57-48ff-ad9f-3084ef402443 ProvOperationsCleanContext
1c308b42-b4b4-42ad-864c-48440c12b7a5
1ee026d0-f551-4c71-aea2-f9897b159eaf User OOBE Controller Auto Elevated
2134da04-4faa-42ed-ada2-43707b4e1de1 
2b2cad40-19c1-4794-b32d-397e41d5e8a7 User OOBE Controller
2c012f55-1318-44f4-a235-20c4df918fb3 Cloud Domain Join OS Upgrade Helper
3a965ed4-0e14-4a1b-a71e-972f1c1044f6 CloudExperienceHost Util Elevated Manager
40afa0b6-3b2f-4654-8c3f-161de85cf80e Connected User Store
4c1b3c1d-5c78-4a73-be8b-de1ec4b3637e 
54337179-c8b2-4ed4-95e4-95601c850d8c 
558c258c-90fe-401c-8772-7edca8016d2c 
6447e897-294b-409a-bf15-5f349a20f2c0 OOBE Registered Owner
80a90d72-a834-4f3d-ad3b-c7abbe4a0f66 OOBE User Authentication
973e4ce8-85a2-4207-8147-4778b50644db Azure AD Join with Authentic User Gesture
9a31d292-655f-48f7-b5ad-553358bcd0c9 
9caf4a2e-c957-48c7-b4d2-4d11188e0b94 OOBE Elevated Util
9dea6e0b-8856-45d8-a424-57244aef1e3c 
a3987437-f1b5-4296-a7dd-6cc3a8b738b9 
b742e827-ede6-400f-8312-cd522198be86 
d2b3db04-b843-11e7-abc4-cec278b6b50a 
d2d28389-85ee-4f9c-b45f-58bd9e664976 
df3460ae-d92d-40f3-b5cd-f83259936f23 
df436197-c14c-4f1d-99cc-4c7bbb399a2f 
e1f5aa5b-065c-4e29-b454-c1bbfe0819d2 Microsoft Account Credential Manager
efeb5035-1da0-4b73-afa2-68ed7a1d98e0 RetailInfoSetterInternal
f32fcfec-9054-470a-acee-867f2277b772 
fd5a78d9-c2f5-45ff-9097-c615acd0aa51 

I’ve not gone through the whole list, but a few stand out including “Connected User Store” which allows you to link a local account to an online account and “54337179-c8b2-4ed4-95e4-95601c850d8c” which exposes a Local Account Manager class. The class registrations do have AutoElevationAllowed value, which might limit attack surface (although both these classes have the value set to 1). However the broker doesn’t seem to check the value anyway.

Let’s focus on the Local Account Manager class, it has a number of interfaces, but most interesting is ILocalAccountManager. This has functions such as:

CreateAccount - Create an arbitrary local user account.
CreateRetailDemoAccount - Create an account for Retail Demo mode.
UpdateRecoveryData - Update an account’s recovery questions.

For illustrative purposes the CreateRetailDemoAccount will create a new user account in the Administrators group with an empty password. However it’s supposed to be used as part of setting up Retail Demo Mode which needs administrator privileges if done through the Settings App. This is a pretty trivial EoP:

Start the scheduled task.
Create the COM server.
Create the Local Account Manager class.
Call CreateRetailDemoAccount to create the administrator account.
Login as that user to get admin privileges.

If you’re okay with user interaction running privileged code as the new user is easy, just use UAC over the shoulder elevation or logout then back in as the user. If no user interaction then it’s a bit harder as by default you can’t authenticate without a password, however a few of the other classes including Connected User Store will temporarily disable the empty password check for its own purposes so there’s likely an exploitable race window where the system doesn’t enforce the check and so the user could call CreateProcessWithLogon to create a process, or LogonUser to get an impersonation token with the empty password.

This task is similar in behavior to a previous bug I reported back in 2015 (CVE-2015-2528) which was in the Microsoft\Windows\Shell\CreateObjectTask scheduled task. I don’t know if any lessons were learnt from that issue. Specifically the COM classes which the broker hosts aren’t necessarily designed to be hosted in a SYSTEM COM server accessible from a normal user. I think hiding a SYSTEM COM Server behind a Scheduled Task has the feeling of a backdoor.

Fixing wise there really should be no reason that the INTERACTIVE group can access or activate the system COM server. Realistically I don’t think the user should even be able to start the scheduled task at all. I think it’s a game of whack-a-mole to try and “fix” the hosted COM classes.

Proof of Concept:

I’ve provided a PoC as a C# project. It’ll create the admin Retail Demo User which will be an administrator. It doesn’t attempt to use the user afterwards though, but you can clearly see that it has been added. If you really want to test it then just logout and log back in as the new user.

1) Compile the C# project.
2) Run the PoC as a normal user.
3) Check members of the Administrators group.

Expected Result:
Fails to access the SYSTEM COM server.

Observed Result:
SYSTEM COM Server accessed and the user ‘Darrin DeYoung’ is created which is a member of the Administrators group.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse,
the bug report will become visible to the public. The scheduled disclosure
date is 2020-09-02. Disclosure at an earlier date is also possible if
agreed upon by all parties.


Related CVE Numbers: CVE-2020-1471,CVE-2015-2528



Found by: forshaw@google.com

### Windows: StorageFolder Marshaled Object Access Check Bypass EoP

Windows: StorageFolder Marshaled Object Access Check Bypass EoP
Platform: Windows 10 2004/1909
Class: Elevation of Privilege
Security Boundary: AppContainer

Summary:
 The StorageFolder class when used out of process can bypass security checks to read and write files not allowed to an AppContainer.

Description:

When a StorageFolder object is passed between processes it's custom marshaled using the CStorageFolderProxy class (CLSID: a5183349-82de-4bfc-9c13-7d9dc578729c) in windows.storage.dll. The custom marshaled data contains three values, a standard marshaled OBJREF for a Proxy instance in the originating process, a standard marshaled OBJREF for the original CStorageFolder object and a Property Store.

When the proxy is unmarshaled the CStorageFolderProxy object is created in the client process, this redirects any calls to the storage interfaces to the creating process's CStorageFolder instance. The CStorageFolder will check access based on the COM caller. 

However, something different happens if you call a method on the marshaled Proxy object. The call will be made to the original process's Proxy object, which will then call the real CStorageFolder method. The problem is the Proxy and the real object are running in different Apartments, the Proxy in the MTA and the real object in a STA. This results in the call to the real object being Cross-Apartment marshaled, this breaks the call context for the thread as it's not passed to the other apartment. As shown in a rough diagram.

[ Client (Proxy::Call) ] => [Server [ MTA (Proxy::Call) ] => [ STA (Real::Call) ] ]

As the call context is only captured by the real object this results in the real object thinking it's being called by the same process, not the AppContainer process. If the process hosting the StorageFolder is more privileged this can result in being able to read/write arbitrary files in specific directories. Note that CStorageFile is similarly affected, but I'm only describing CStorageFolder. In any case it's almost certainly the shared code which is a problem.

I've no idea why the classes aren't using the FTM, perhaps they're not marked as Agile? If they were then the real object would be called directly and so would still be running in the original caller's context. Even if the FTM was enabled and the call context was maintained it's almost certainly possible to construct the proxy in a more privileged, but different process because of the asymmetric nature of the marshaling, invoke methods in that process which will always have to be performed out of process.

Fixing wise, firstly I don't think the Proxy should ever end up standard marshaled to out of process callers, removing that might help. Also when a call is made to the real implementation perhaps you need to set a Proxy Blanket or enable dynamic cloaking and impersonate before the call. There does seem to be code to get the calling process handle as well, so maybe that also needs to be taken into consideration?

This code looks like it's copied and pasted from SHCORE which is related to the bugs I've already reported. Perhaps the Proxy is not supposed to be passed back in the marshal code, but the copied code does that automatically? I'd highly recommend you look at any code which uses the same CFTMCrossProcClientImpl::_UnwrapStream code and verify they're all correct.

Proof of Concept:

I've provided a PoC as a C# project. The code creates an AppContainer process (using a temporary profile). It then uses the Partial Trust StorageFolderStaticsBrokered class, which is instantiated OOP inside a RuntimeBroker instance. The class allows opening a StorageFolder object to the AC profile's Temporary folder. The StorageFolderStaticsBrokered is granted access to any AC process as well as the \u"lpacAppExperience\u" capability which means it also works from Classic Edge LPAC.

The PoC then uses the IStorageItem2::GetParentAsync method to walk up the directory hierarchy until it reaches %LOCALAPPDATA%. It can't go any higher than that as there seems to be some condition restriction in place, probably as it's the base location for package directories. The code then writes an arbitrary file abc.txt to the Microsoft sub-directory. Being able to read and write arbitrary files in the user's Local AppData is almost certainly enough to escape the sandbox but I've not put that much time into it.

1) Compile the C# project. It will need to grab the NtApiDotNet from NuGet to work.
2) Run the POC executable.

Expected Result:
Accessing files outside of the AppContainers directory is blocked.

Observed Result:
An arbitrary file is written to the %LOCALAPPDATA%\\Microsoft directory.

This bug is subject to a 90 day disclosure deadline. After 90 days elapse,
the bug report will become visible to the public. The scheduled disclosure
date is 2020-09-23. Disclosure at an earlier date is also possible if
agreed upon by all parties.

Related CVE Numbers: CVE-2020-0886.



Found by: forshaw@google.com
