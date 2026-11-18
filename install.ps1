[CmdletBinding()]
param(
    [string]$Wheel = "",
    [ValidateSet("", "known-good", "latest")]
    [string]$Choice = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Say([string]$Text) { Write-Host $Text }
function Ok([string]$Text) { Say "[+] $Text" }
function Info([string]$Text) { Say "[*] $Text" }
function Die([string]$Text) { Write-Host "[!] $Text"; exit 1 }

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Here

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Die "Git for Windows is needed (git and its bash): install it from https://git-scm.com/download/win and run this again"
}
$GitBash = Join-Path (Split-Path -Parent (Split-Path -Parent (Get-Command git).Source)) "bin\bash.exe"
if (-not (Test-Path $GitBash)) {
    Die "Git for Windows' bash was not found beside git: git-secrets needs it. Install Git for Windows, not another git"
}

function GitOut([string[]]$Arguments) {
    $ErrorActionPreference = "Continue"
    $Out = (& git @Arguments 2>&1 | ForEach-Object { "$_" })
    $script:GitCode = $LASTEXITCODE
    return ($Out -join "`n")
}

$Build = $false
if ($Wheel) {
    if (-not (Test-Path $Wheel -PathType Leaf)) { Die "no wheel at $Wheel" }
    $Wheel = (Resolve-Path $Wheel).Path
    if ((Split-Path -Leaf $Wheel) -notmatch '^gitmortem-([0-9][0-9.]*)-py3-none-any\.whl$') {
        Die "$Wheel is not a GitMortem wheel"
    }
    $Version = $Matches[1]
} elseif (Test-Path (Join-Path $Here ".git")) {
    $Top = GitOut @("rev-parse", "--show-toplevel")
    if ($script:GitCode -ne 0 -or -not $Top) {
        Die "git cannot read this checkout, so its release tag cannot be read: $(($Top -split "`n")[0])"
    }
    if ((Resolve-Path $Top).Path -ne (Resolve-Path $Here).Path) {
        Die "git reads $Top as this checkout's top, not $($Here): run this from the checkout's top"
    }
    $Tag = GitOut @("describe", "--tags", "--exact-match", "--match", "v[0-9]*")
    if ($script:GitCode -eq 0 -and $Tag) {
        $Version = $Tag.Substring(1)
    } else {
        $Build = $true
        $Head = GitOut @("rev-parse", "--short", "HEAD")
        $From = if ($script:GitCode -eq 0) { "commit $Head" } else { "commit not yet made" }
        if (GitOut @("status", "--porcelain")) { $From = "$From, with uncommitted changes" }
        Info "this checkout is not at a release tag: building GitMortem from it ($From)"
    }
} else {
    $Build = $true
    Info "this folder is no release tag's checkout: building GitMortem from it"
}

switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { $Target = "x86_64-pc-windows-msvc" }
    "ARM64" { $Target = "aarch64-pc-windows-msvc" }
    default { Die "no install for Windows on $($env:PROCESSOR_ARCHITECTURE): x86_64 or arm64 only" }
}

$Root = Join-Path $env:LOCALAPPDATA "GitMortem\app"
$Bin = Join-Path $Root "bin"
New-Item -ItemType Directory -Force -Path $Bin | Out-Null
$Work = Join-Path ([IO.Path]::GetTempPath()) ("gitmortem-install-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $Work | Out-Null

function Fetch([string]$Url, [string]$Out) {
    if (-not $Url.StartsWith("https://")) { Die "only HTTPS is used: $Url" }
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Out
}
function Sha256([string]$Path) { (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant() }

function NodeFits([string]$Node) {
    try { $V = (& $Node --version 2>$null) } catch { return $false }
    if ($V -notmatch '^v?(\d+)\.(\d+)\.') { return $false }
    $Major = [int]$Matches[1]
    $Minor = [int]$Matches[2]
    if ($Major -eq 20) { return $Minor -ge 19 }
    if ($Major -eq 22) { return $Minor -ge 12 }
    return $Major -ge 23
}

function UseNode {
    $Node = Get-Command node -ErrorAction SilentlyContinue
    $Npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if ($Node -and $Npm -and (NodeFits $Node.Source)) {
        Info "the frontend, with Node.js $(& $Node.Source --version) from this machine"
        return
    }
    $NodePins = Get-Content (Join-Path $Here "packaging\node-version.txt")
    $NodeVersion = ($NodePins | Where-Object { $_ -match '^version ' } | ForEach-Object { ($_ -split ' ')[1] })
    $Line = ($NodePins | Where-Object { $_ -match "^sha256 $([regex]::Escape($Target)) " })
    if (-not $NodeVersion -or -not $Line) {
        Die "no Node.js 20.19+ or 22.12+ here, and packaging\node-version.txt names none for $($Target): install Node.js and run this again, or pass -Wheel FILE"
    }
    $Plat = ($Line -split ' ')[2]
    $NodeSha = ($Line -split ' ')[3]
    $Dir = Join-Path $Root "node\$NodeVersion-$Target"
    $Exe = Join-Path $Dir "node.exe"
    $Have = if (Test-Path $Exe) { (& $Exe --version) } else { "" }
    if ($Have -ne $NodeVersion) {
        Info "Node.js $NodeVersion, for the frontend (this machine has none 20.19+ or 22.12+)"
        $Zip = Join-Path $Work "node.zip"
        Fetch "https://nodejs.org/dist/$NodeVersion/node-$NodeVersion-$Plat.zip" $Zip
        if ((Sha256 $Zip) -ne $NodeSha) { Die "Node.js $NodeVersion does not match the SHA-256 recorded for it" }
        Expand-Archive -Path $Zip -DestinationPath (Join-Path $Work "node") -Force
        $Fresh = Join-Path $Work "node\node-$NodeVersion-$Plat"
        $Ran = (& (Join-Path $Fresh "node.exe") --version 2>$null)
        if ($Ran -ne $NodeVersion) { Die "Node.js $NodeVersion does not run on this machine, or says it is another: install Node.js and run this again, or pass -Wheel FILE" }
        New-Item -ItemType Directory -Force -Path (Join-Path $Root "node") | Out-Null
        if (Test-Path $Dir) { Remove-Item -Recurse -Force $Dir }
        Move-Item $Fresh $Dir
    } else {
        Info "the frontend, with Node.js $NodeVersion from $Dir"
    }
    $env:PATH = "$Dir;$env:PATH"
}

function NpmStep([string]$Name, [string[]]$Arguments) {
    $Log = Join-Path $Work "npm.log"
    $env:npm_config_update_notifier = "false"
    $ErrorActionPreference = "Continue"
    & npm.cmd --prefix (Join-Path $Here "frontend") @Arguments *> $Log
    $Code = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    if ($Code -ne 0) {
        Get-Content $Log -Tail 40 | Write-Host
        Die "the frontend did not build (npm $Name)"
    }
}

function BuildWheel {
    UseNode
    NpmStep "ci" @("ci", "--no-audit", "--no-fund")
    NpmStep "run build" @("run", "build")
    Info "the wheel, its build dependencies by hash from uv.lock"
    $Constraints = Join-Path $Work "build-constraints.txt"
    & $Uv export -q --project $Here --frozen --only-group build --no-emit-project --format requirements-txt --output-file $Constraints
    if ($LASTEXITCODE -ne 0) { Die "uv could not read uv.lock" }
    $Dist = Join-Path $Work "dist"
    & $Uv build -q --wheel --python $Python --build-constraints $Constraints --require-hashes --out-dir $Dist $Here
    if ($LASTEXITCODE -ne 0) { Die "uv could not build the wheel" }
    $Built = @(Get-ChildItem -Path $Dist -Filter "gitmortem-*-py3-none-any.whl")
    if ($Built.Count -ne 1) { Die "uv build left no single GitMortem wheel in $Dist" }
    $Said = (& $Python -I (Join-Path $Here "scripts\build_package.py") --check $Built[0].FullName)
    if ($LASTEXITCODE -ne 0) {
        Die "the wheel built from this checkout is not whole: $((($Said -join ' ') -replace '^\[!\] ', ''))"
    }
    if ($Built[0].Name -notmatch '^gitmortem-([0-9][0-9.]*)-py3-none-any\.whl$') { Die "$($Built[0].Name) is not a GitMortem wheel" }
    $script:Version = $Matches[1]
    $script:Wheel = $Built[0].FullName
}

try {
    $Pins = Get-Content (Join-Path $Here "packaging\uv-version.txt")
    $UvVersion = ($Pins | Where-Object { $_ -match '^version ' } | ForEach-Object { ($_ -split ' ')[1] })
    $UvSha = ($Pins | Where-Object { $_ -match "^sha256 $([regex]::Escape($Target)) " } | ForEach-Object { ($_ -split ' ')[2] })
    if (-not $UvVersion -or -not $UvSha) { Die "packaging\uv-version.txt names no uv for $Target" }
    $Uv = Join-Path $Bin "uv.exe"
    $Have = if (Test-Path $Uv) { ((& $Uv --version) -split ' ')[1] } else { "" }
    if ($Have -ne $UvVersion) {
        Info "uv $UvVersion"
        $Zip = Join-Path $Work "uv.zip"
        Fetch "https://github.com/astral-sh/uv/releases/download/$UvVersion/uv-$Target.zip" $Zip
        if ((Sha256 $Zip) -ne $UvSha) { Die "uv $UvVersion does not match the SHA-256 recorded for it" }
        Expand-Archive -Path $Zip -DestinationPath (Join-Path $Work "uv") -Force
        Copy-Item -Force (Join-Path $Work "uv\uv.exe") $Uv
    }

    $env:UV_PYTHON_INSTALL_DIR = Join-Path $Root "python"
    $env:UV_CACHE_DIR = Join-Path $Root "cache"
    $env:UV_NO_CONFIG = "1"
    & $Uv python install -q 3.12; if ($LASTEXITCODE -ne 0) { Die "uv could not install Python 3.12" }
    $Python = (& $Uv python find --managed-python 3.12)
    if ($LASTEXITCODE -ne 0 -or -not $Python) { Die "uv could not find its Python 3.12" }
    if ($Build) {
        BuildWheel
    } elseif (-not $Wheel) {
        $Origin = GitOut @("remote", "get-url", "origin")
        if ($Origin -notmatch '^(https://github\.com/|git@github\.com:|ssh://git@github\.com/)([^/]+/[^/.]+)(\.git)?/?$') {
            Die "origin is not a GitHub repository, so the release's wheel cannot be found: pass -Wheel FILE"
        }
        $Slug = $Matches[2]
        $Name = "gitmortem-$Version-py3-none-any.whl"
        $Base = "https://github.com/$Slug/releases/download/$Tag"
        Info "GitMortem $Version from $Slug's release $Tag"
        $Wheel = Join-Path $Work $Name
        $Sums = Join-Path $Work "SHA256SUMS"
        foreach ($File in @(@($Name, $Wheel), @("SHA256SUMS", $Sums))) {
            try { Fetch "$Base/$($File[0])" $File[1] }
            catch { Die "GitHub did not serve $($File[0]) for release $($Tag) of $($Slug): once the release is published and the repository public, run this again, or pass -Wheel FILE" }
        }
        $Listed = (Get-Content $Sums | Where-Object { $_ -match "^([0-9a-f]{64}) [ *]$([regex]::Escape($Name))$" } | ForEach-Object { $Matches[1] })
        $Actual = Sha256 $Wheel
        if (-not $Listed -or $Actual -ne $Listed) { Die "$Name does not match the release's SHA256SUMS" }
        try {
            $Api = Invoke-RestMethod -UseBasicParsing -Headers @{ "User-Agent" = "gitmortem-installer" } -Uri "https://api.github.com/repos/$Slug/releases/tags/$Tag"
        } catch {
            Die "GitHub did not answer for release $($Tag), so the wheel cannot be checked against its record: GitHub answers 60 such requests an hour from one address, so try again later"
        }
        $Digest = ($Api.assets | Where-Object { $_.name -eq $Name } | ForEach-Object { $_.digest })
        if (-not $Digest) { Die "GitHub's record of release $($Tag) names no digest for $Name" }
        if ($Digest -ne "sha256:$Actual") { Die "$Name does not match GitHub's digest for it" }
    }
    $WheelSha = Sha256 $Wheel

    $Release = Join-Path $Root "releases\$Version-$($WheelSha.Substring(0, 12))"
    $Marker = Join-Path $Release ".gitmortem-complete"
    if ((Test-Path $Marker) -and ((Get-Content $Marker -Raw).Trim() -eq $WheelSha)) {
        Ok "GitMortem $Version already in $Release"
    } else {
        Info "Python 3.12 and GitMortem $Version's environment"
        & $Uv venv -q --clear --python 3.12 $Release; if ($LASTEXITCODE -ne 0) { Die "uv could not make the environment" }
        $Requirements = Join-Path $Work "requirements.txt"
        & $Uv export -q --project $Here --format requirements-txt --no-dev --no-emit-project --frozen --output-file $Requirements
        if ($LASTEXITCODE -ne 0) { Die "uv could not read uv.lock" }
        & $Uv pip install -q --python $Release --require-hashes -r $Requirements
        if ($LASTEXITCODE -ne 0) { Die "the libraries did not install by their hashes" }
        & $Uv pip install -q --python $Release --no-deps $Wheel
        if ($LASTEXITCODE -ne 0) { Die "GitMortem did not install" }
        Set-Content -Path $Marker -Value $WheelSha -Encoding ASCII
        Ok "GitMortem $Version in $Release"
    }

    if (-not $Choice) {
        Say "Install the scanners known-good (the versions this GitMortem was tested with)"
        Say "or latest (each tool's newest compatible release at least 7 days old)?"
        do { $Choice = Read-Host "[known-good/latest]" } until ($Choice -in @("known-good", "latest"))
    }
    $Exe = Join-Path $Release "Scripts\gitmortem.exe"
    $Shim = Join-Path $Bin "gitmortem.cmd"
    $FromShim = "..\releases\$(Split-Path -Leaf $Release)\Scripts\gitmortem.exe"
    if ($FromShim -notmatch '^[A-Za-z0-9.+_\\-]+$') { Die "the release folder's name is not plain ASCII: $FromShim" }
    Set-Content -Path $Shim -Value "@`"%~dp0$FromShim`" %*" -Encoding ASCII
    & $Exe install-scanners --choice $Choice
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if (($env:PATH -split ';') -contains $Bin) {
        Ok "Run: $(Join-Path $Here 'run.ps1') (or, from anywhere: gitmortem local)"
    } else {
        Ok "Run: $(Join-Path $Here 'run.ps1') (add $Bin to your PATH to type gitmortem local from anywhere)"
    }
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $Work
}
