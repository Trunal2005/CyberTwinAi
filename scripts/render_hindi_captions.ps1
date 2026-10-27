param([Parameter(Mandatory = $true)][string]$Manifest)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$entries = Get-Content -LiteralPath $Manifest -Raw -Encoding UTF8 | ConvertFrom-Json
$captionFont = New-Object System.Drawing.Font('Nirmala UI', 31, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
$brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(231, 240, 250))
$format = New-Object System.Drawing.StringFormat
$format.Trimming = [System.Drawing.StringTrimming]::Word
foreach ($entry in $entries) {
    if (Test-Path -LiteralPath $entry.file) { continue }
    $bitmap = New-Object System.Drawing.Bitmap(1690, 108)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.Clear([System.Drawing.Color]::Transparent)
    $graphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $rectangle = New-Object System.Drawing.RectangleF(0, 0, 1690, 108)
    $graphics.DrawString([string]$entry.text, $captionFont, $brush, $rectangle, $format)
    $bitmap.Save([string]$entry.file, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bitmap.Dispose()
}
$format.Dispose()
$captionFont.Dispose()
$brush.Dispose()
Write-Output "Rendered $($entries.Count) Hindi caption groups with Windows text shaping."
