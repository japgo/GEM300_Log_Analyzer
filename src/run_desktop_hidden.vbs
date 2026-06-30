Set shell = CreateObject("Wscript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
appRoot = fso.GetParentFolderName(WScript.ScriptFullName)
packageRoot = fso.GetParentFolderName(appRoot)
shell.Run Chr(34) & packageRoot & "\run_desktop.bat" & Chr(34), 0, False
