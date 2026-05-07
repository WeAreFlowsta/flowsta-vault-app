; Tauri NSIS installer hooks for the "Sign It with Flowsta Vault" right-click
; context menu integration on Windows.
;
; HKCU is used so a per-user install (Tauri's default `installMode`) doesn't
; require admin elevation. The same registry path lives under HKEY_CLASSES_ROOT
; at runtime, so File Explorer picks up the menu item for any file type.

!macro NSIS_HOOK_POSTINSTALL
  WriteRegStr HKCU "Software\Classes\*\shell\FlowstaVaultSign" "" "Sign It with Flowsta Vault"
  WriteRegStr HKCU "Software\Classes\*\shell\FlowstaVaultSign" "Icon" "$INSTDIR\${MAINBINARYNAME}.exe"
  WriteRegStr HKCU "Software\Classes\*\shell\FlowstaVaultSign\command" "" '"$INSTDIR\${MAINBINARYNAME}.exe" "%1"'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DeleteRegKey HKCU "Software\Classes\*\shell\FlowstaVaultSign"
!macroend
