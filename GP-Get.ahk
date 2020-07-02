#NoEnv  ; Recommended for performance and compatibility with future AutoHotkey releases.
; #Warn  ; Enable warnings to assist with detecting common errors.
SendMode Input  ; Recommended for new scripts due to its superior speed and reliability.
SetWorkingDir %A_ScriptDir%  ; Ensures a consistent starting directory.

clipboard := ""
Run, C:\GPO\group-policy.inf
WinWait, group-policy.inf - Notepad
Send ^a^c
sleep, 100
WinClose
Run, notepad.exe
WinWait, Untitled - Notepad
Send ^v^S
Send C:\GPO\group-policy.ini{Enter}
Loop 10 {
  If WinExist("Confirm Save As"){
    Send, !y
  } else {
    Sleep, 250
  }
}
while WinExist("group-policy.ini - Notepad"){
  WinClose group-policy.ini - Notepad
  sleep 250
}
