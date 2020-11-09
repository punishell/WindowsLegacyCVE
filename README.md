# WindowsLegacyCVE

## CVE-2018-0748
```
Windows: NTFS Owner/Mandatory Label Privilege Bypass EoP 




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

```


## CVE-2018-0752
```
Windows: NtImpersonateAnonymousToken LPAC to Non-LPAC EoP 

CVE-2018-0752


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


```

## CVE-2018-0823
```
Windows: NPFS Symlink Security Feature Bypass/Elevation of Privilege/Dangerous Behavior 



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


```

## CVE-2018-0826
```
Windows: StorSvc SvcMoveFileInheritSecurity Arbitrary File Creation EoP 

CVE-2018-0826


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


```

## CVE-2018-0982
```
Windows: Child Process Restriction Mitigation Bypass 

CVE-2018-0982


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


```
