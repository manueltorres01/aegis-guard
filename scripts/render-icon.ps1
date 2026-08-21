$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$projectRoot = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $projectRoot 'build\icon.png'
$bitmap = [Drawing.Bitmap]::new(256, 256, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
$graphics = [Drawing.Graphics]::FromImage($bitmap)
$backgroundPath = [Drawing.Drawing2D.GraphicsPath]::new()
$shieldPath = [Drawing.Drawing2D.GraphicsPath]::new()
$backgroundBrush = $null
$shieldPen = $null
$checkPen = $null

try {
  $graphics.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $graphics.Clear([Drawing.Color]::Transparent)

  $radius = 56
  $diameter = $radius * 2
  $backgroundPath.AddArc(8, 8, $diameter, $diameter, 180, 90)
  $backgroundPath.AddArc(248 - $diameter, 8, $diameter, $diameter, 270, 90)
  $backgroundPath.AddArc(248 - $diameter, 248 - $diameter, $diameter, $diameter, 0, 90)
  $backgroundPath.AddArc(8, 248 - $diameter, $diameter, $diameter, 90, 90)
  $backgroundPath.CloseFigure()
  $backgroundBrush = [Drawing.Drawing2D.LinearGradientBrush]::new(
    [Drawing.Point]::new(32, 24),
    [Drawing.Point]::new(224, 232),
    [Drawing.ColorTranslator]::FromHtml('#3b82f6'),
    [Drawing.ColorTranslator]::FromHtml('#4f46e5')
  )
  $graphics.FillPath($backgroundBrush, $backgroundPath)

  $shieldPath.StartFigure()
  $shieldPath.AddLine(128, 48, 194, 74)
  $shieldPath.AddLine(194, 74, 194, 122)
  $shieldPath.AddBezier(194, 122, 194, 164, 169, 195, 128, 220)
  $shieldPath.AddBezier(128, 220, 87, 195, 62, 164, 62, 122)
  $shieldPath.AddLine(62, 122, 62, 74)
  $shieldPath.CloseFigure()
  $shieldPen = [Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml('#eef6ff'), 15)
  $shieldPen.LineJoin = [Drawing.Drawing2D.LineJoin]::Round
  $graphics.DrawPath($shieldPen, $shieldPath)

  $checkPen = [Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml('#a7f3d0'), 17)
  $checkPen.StartCap = [Drawing.Drawing2D.LineCap]::Round
  $checkPen.EndCap = [Drawing.Drawing2D.LineCap]::Round
  $checkPen.LineJoin = [Drawing.Drawing2D.LineJoin]::Round
  $graphics.DrawLines($checkPen, @([Drawing.Point]::new(94, 131), [Drawing.Point]::new(116, 153), [Drawing.Point]::new(164, 99)))

  $bitmap.Save($destination, [Drawing.Imaging.ImageFormat]::Png)
} finally {
  if ($checkPen) { $checkPen.Dispose() }
  if ($shieldPen) { $shieldPen.Dispose() }
  if ($backgroundBrush) { $backgroundBrush.Dispose() }
  $shieldPath.Dispose()
  $backgroundPath.Dispose()
  $graphics.Dispose()
  $bitmap.Dispose()
}

