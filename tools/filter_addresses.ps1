# filter_addresses.ps1
#
# Reads a TSV / list of Bitcoin addresses (such as the blockchair dump) and
# writes out only the entries that the modernised BitCrack pipeline can match
# against on the GPU:
#
#   * P2PKH      -> base58 addresses starting with '1'
#   * P2WPKH v0  -> bech32 addresses "bc1q..." with a 42-char total length
#                   (witness version 0, 20-byte program = hash160 of pubkey)
#
# P2SH ('3...'), P2WSH (62-char bc1q...) and Taproot ('bc1p...') are skipped
# because they do not commit to RIPEMD160(SHA256(pubkey)) and therefore cannot
# be brute-forced with the same kernel.
#
# Usage:
#   .\filter_addresses.ps1 -InputPath ..\blockchair_bitcoin_addresses_latest.tsv `
#                          -OutputPath ..\bitcrack_targets.txt

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $InputPath,
    [Parameter(Mandatory = $true)] [string] $OutputPath
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $InputPath)) {
    throw "Input file not found: $InputPath"
}

$inFull  = (Resolve-Path -LiteralPath $InputPath).Path
$outFull = [System.IO.Path]::GetFullPath($OutputPath)

$reader = [System.IO.StreamReader]::new($inFull)
$writer = [System.IO.StreamWriter]::new($outFull, $false, [System.Text.UTF8Encoding]::new($false))
$writer.NewLine = "`n"

$total = 0
$p2pkh = 0
$p2wpkh = 0
$skipped = 0

try {
    while (($line = $reader.ReadLine()) -ne $null) {
        $total++

        $tab = $line.IndexOf("`t")
        if ($tab -ge 0) { $line = $line.Substring(0, $tab) }
        $line = $line.Trim()
        if ($line.Length -eq 0) { continue }

        $first = $line[0]
        if ($first -eq '1') {
            # P2PKH: 26-35 base58 chars.
            if ($line.Length -ge 26 -and $line.Length -le 35) {
                $writer.WriteLine($line)
                $p2pkh++
                continue
            }
        }
        elseif ($line.Length -eq 42 -and $line.StartsWith('bc1q', [System.StringComparison]::OrdinalIgnoreCase)) {
            # Native P2WPKH (witness v0, 20-byte program). 'bc' + '1' + 'q' + 38 data chars = 42.
            $writer.WriteLine($line.ToLowerInvariant())
            $p2wpkh++
            continue
        }

        $skipped++
    }
}
finally {
    $reader.Dispose()
    $writer.Dispose()
}

$kept = $p2pkh + $p2wpkh
Write-Host ("Total lines read : {0}" -f $total)
Write-Host ("  P2PKH kept     : {0}" -f $p2pkh)
Write-Host ("  P2WPKH kept    : {0}" -f $p2wpkh)
Write-Host ("  Skipped        : {0}" -f $skipped)
Write-Host ("Wrote {0} addresses to {1}" -f $kept, $outFull)
