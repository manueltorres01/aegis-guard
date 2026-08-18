# Responding to a suspected Windows infection

Aegis Guard is a supplemental scanner, not an incident-response service. If you believe a computer is actively compromised:

1. Disconnect it from untrusted networks. Do not sign in to banking, email or administrator accounts from that device.
2. From Windows Security, update Microsoft Defender and run a **Full scan**, followed by **Microsoft Defender Offline scan**. Microsoft documents the current scan options in [Virus & threat protection in Windows Security](https://support.microsoft.com/en-us/windows/virus-and-threat-protection-in-the-windows-security-app-1362f4cd-d71a-b52a-0b66-c2820032b65e).
3. Preserve Aegis reports and quarantine metadata. Do not restore a detection until it has been reviewed.
4. From a separate trusted device, change important passwords and revoke active sessions, especially email and password-manager sessions. Enable multifactor authentication.
5. Check for unauthorized financial or account activity. Contact the relevant provider when necessary.
6. For business devices, regulated data, ransomware, persistent re-detection or signs of credential theft, contact a qualified incident-response professional.
7. When confidence in the system cannot be restored, back up only necessary documents and follow Microsoft's official [Windows recovery options](https://support.microsoft.com/en-us/windows/experience/backup-recovery/recovery-options-in-windows) to reset or reinstall from trusted media. Fully update Windows before restoring carefully scanned data.

## Using Aegis as a second opinion

Start with reporting-only mode:

```powershell
node .\src\cli.mjs scan "$env:USERPROFILE\Downloads" --json
```

Review the findings. If you choose automatic containment, use `--quarantine`. Quarantine is reversible; permanent deletion is intentionally not exposed by the CLI.

Never upload private documents or unknown samples to a public GitHub issue.
