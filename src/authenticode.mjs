import { execFile } from 'node:child_process';

const POWERSHELL = `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
const WINDOWS_MODULES = `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\WindowsPowerShell\\v1.0\\Modules`;
const SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$targetPath = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__TARGET_BASE64__'))",
  "$signatureError = ''",
  "try { $signature = Get-AuthenticodeSignature -LiteralPath $targetPath } catch { $signatureError = $_.Exception.Message }",
  "$subject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '' }",
  "$organization = if ($subject -match '(?:^|,\\s*)O=([^,]+)') { $Matches[1].Trim() } else { '' }",
  "$status = if ($signature) { $signature.Status.ToString() } else { 'Error' }",
  "[pscustomobject]@{ Status = $status; Subject = $subject; Organization = $organization; IsOSBinary = ($signature.IsOSBinary -eq $true); Error = $signatureError } | ConvertTo-Json -Compress"
].join('; ');

export function createAuthenticodeVerifier({ cacheSize = 10_000, timeoutMs = 8_000 } = {}) {
  const cache = new Map();
  return async (file, sha256) => {
    if (process.platform !== 'win32') return { status: 'unsupported', subject: '', organization: '' };
    const key = String(sha256 || file).toLowerCase();
    if (cache.has(key)) return cache.get(key);
    const value = await verify(file, timeoutMs);
    cache.set(key, value);
    while (cache.size > cacheSize) cache.delete(cache.keys().next().value);
    return value;
  };
}

function verify(file, timeoutMs) {
  return new Promise((resolve, reject) => {
    const targetBase64 = Buffer.from(file, 'utf8').toString('base64');
    const command = SCRIPT.replace('__TARGET_BASE64__', targetBase64);
    const encodedCommand = Buffer.from(command, 'utf16le').toString('base64');
    execFile(POWERSHELL, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encodedCommand], {
      windowsHide: true,
      timeout: timeoutMs,
      maxBuffer: 64 * 1024,
      env: {
        ...process.env,
        PSModulePath: [WINDOWS_MODULES, process.env.PSModulePath].filter(Boolean).join(';')
      }
    }, (error, stdout) => {
      if (error) return reject(error);
      try {
        const parsed = JSON.parse(stdout.trim());
        resolve({
          status: String(parsed.Status ?? '').toLowerCase() === 'valid' ? 'valid' : 'invalid',
          subject: String(parsed.Subject ?? ''),
          organization: String(parsed.Organization ?? ''),
          isOsBinary: parsed.IsOSBinary === true
        });
      } catch (parseError) { reject(parseError); }
    });
  });
}
