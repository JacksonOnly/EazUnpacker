#requires -Version 7.0
[CmdletBinding()]
param(
    [string]$Version='1.3.0',
    [string]$Ref='HEAD',
    [string]$OutputDirectory=(Join-Path $PSScriptRoot '..\artifacts\releases')
)
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
if($Version -notmatch '^\d+\.\d+\.\d+$'){throw 'Version must have major.minor.patch format.'}
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$output=[IO.Path]::GetFullPath($OutputDirectory)
$resolved=& git -C $repo rev-parse --verify --end-of-options "$Ref~0"
if($LASTEXITCODE -ne 0){throw 'Cannot resolve the requested commit.'}
$commit=([string]$resolved).Trim()
$snapshotPaths=@(& git -C $repo ls-tree -r --name-only $commit)
if($LASTEXITCODE -ne 0){throw 'Cannot inspect the requested source snapshot.'}
$privatePaths=@($snapshotPaths|Where-Object {
    $_ -match '(?i)(^|/)(AGENTS\.md$|tests?/|__tests__/|screenshots/|samples?[^/]*/|样本[^/]*/|artifacts/|bin/|obj/|temp/|test-results/|reports/|diagnostics/|private/|local/|secrets/)' -or
    $_ -match '(?i)(Tests?\.(cs|csproj)$|\.(exe|dll|pdb|mdb|zip|7z|rar|dmp|binlog|jsonl|pem|key|pfx|p12|strings\.json)$)' -or
    $_ -match '(^|/)\.env($|\.)'
})
if($privatePaths.Count){throw 'Selected snapshot contains local-only files. Commit the privacy cleanup before packaging.'}
if($snapshotPaths -notcontains 'Directory.Build.targets'){throw 'Selected snapshot is missing the private-path build mapping.'}
New-Item -ItemType Directory -Path $output -Force|Out-Null
$name="EazUnpacker-v$Version"
$zip=Join-Path $output "$name-win.zip"
if(Test-Path -LiteralPath $zip){throw "Release already exists: $zip"}
$run=Join-Path $output ("build-$Version-"+[Guid]::NewGuid().ToString('N'))
$source=Join-Path $run 'source'
$stage=Join-Path $run 'package'
$package=Join-Path $stage $name
$verify=Join-Path $run 'verify'
foreach($p in @($run,$source,$package)){New-Item -ItemType Directory -Path $p -Force|Out-Null}
function Remove-ReleaseTemporary([string]$path) {
    $full=[IO.Path]::GetFullPath($path)
    if(!$full.StartsWith($run.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw "Unsafe cleanup target: $full"}
    if(Test-Path -LiteralPath $full){Remove-Item -LiteralPath $full -Recurse -Force}
}
function Copy-ReleaseFile([string]$from,[string]$relative) {
    $to=Join-Path $package $relative
    New-Item -ItemType Directory -Path (Split-Path $to) -Force|Out-Null
    Copy-Item -LiteralPath $from -Destination $to
}
$archive=Join-Path $run "$name-source.zip"
& git -C $repo archive --format=zip "--output=$archive" $commit
if($LASTEXITCODE -ne 0){throw 'Source archive failed.'}
Expand-Archive -LiteralPath $archive -DestinationPath $source
$privateTextPattern='(?i)(?<![a-z0-9])[a-z]:[\\/]|/(?:Users|home)/|\\\\[^\\\s]+\\(?:Users|home|samples?)\\'
foreach($relative in $snapshotPaths){
    if([IO.Path]::GetExtension($relative) -notin '.cs','.csproj','.props','.targets','.ps1','.md','.config','.slnx','.json','.yml','.yaml','.xml'){continue}
    if([IO.File]::ReadAllText((Join-Path $source $relative)) -match $privateTextPattern){throw 'Selected snapshot contains an absolute machine path. Sanitize source and documentation before packaging.'}
}
[xml]$props=Get-Content -LiteralPath (Join-Path $source 'src/Directory.Build.props') -Raw
if([string]$props.Project.PropertyGroup.Version -ne $Version){throw 'Requested version differs from the committed build properties.'}
$sdk=(& dotnet --version).Trim()
& dotnet build (Join-Path $source 'Unpacker.slnx') -c Release --nologo -v minimal *> (Join-Path $run 'build.log')
if($LASTEXITCODE -ne 0){throw "Build failed. See $run\build.log"}
$built=Join-Path $source 'src/bin/Release/net48'
Get-ChildItem -LiteralPath $built -File|Where-Object {
    $_.Extension -in '.exe','.dll','.pdb','.config','.xml','.json' -and $_.Name -notlike 'Unpacker.ModernWorker*'
}|ForEach-Object {Copy-ReleaseFile $_.FullName $_.Name}
Copy-Item -LiteralPath (Join-Path $built 'worker') -Destination (Join-Path $package 'worker') -Recurse
foreach($file in @('README.md','README.en.md','CHANGELOG.md','LICENSE','NOTICE')){Copy-ReleaseFile (Join-Path $source $file) $file}
foreach($file in @('src/ThirdParty/EazFixer/LICENSE','src/ThirdParty/EazyDevirt/LICENSE','src/ThirdParty/Echo/LICENSE.md')){Copy-ReleaseFile (Join-Path $source $file) $file}
Copy-ReleaseFile $archive ("source/$name-source.zip")

# Preserve package license metadata and locally available license texts. No
# network license fetches, cached credentials or sample files enter the release.
$packages=@{}
Get-ChildItem -LiteralPath (Join-Path $source 'src') -Recurse -File -Filter project.assets.json|ForEach-Object {
    $assets=Get-Content -LiteralPath $_.FullName -Raw|ConvertFrom-Json
    foreach($lib in $assets.libraries.PSObject.Properties){
        if($lib.Value.type -ne 'package' -or $packages.ContainsKey($lib.Name)){continue}
        foreach($folder in $assets.packageFolders.PSObject.Properties.Name){
            $directory=Join-Path $folder $lib.Value.path
            if(!(Test-Path -LiteralPath $directory)){continue}
            $nuspec=Get-ChildItem -LiteralPath $directory -Filter '*.nuspec' -File|Select-Object -First 1
            $license='See included package metadata'
            $texts=@(Get-ChildItem -LiteralPath $directory -File|Where-Object {$_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE)(\.|$)'})
            if($nuspec){
                [xml]$metadata=Get-Content -LiteralPath $nuspec.FullName -Raw
                $node=$metadata.SelectSingleNode("//*[local-name()='license']")
                if($node){
                    $license=$node.InnerText
                    if($node.GetAttribute('type') -eq 'file'){
                        $candidate=[IO.Path]::GetFullPath((Join-Path $directory $node.InnerText))
                        if($candidate.StartsWith([IO.Path]::GetFullPath($directory).TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $candidate)){$texts+=Get-Item -LiteralPath $candidate}
                    }
                }
                Copy-ReleaseFile $nuspec.FullName ('licenses/nuget/'+$lib.Name.Replace('/','-')+'/'+$nuspec.Name)
            }
            foreach($text in @($texts|Sort-Object FullName -Unique)){Copy-ReleaseFile $text.FullName ('licenses/nuget/'+$lib.Name.Replace('/','-')+'/'+$text.Name)}
            $packages[$lib.Name]=$license
            break
        }
    }
}
$notices=@('# NuGet package notices','','Direct and transitive build/runtime references from the committed restore. Vendored source licenses are in src/ThirdParty.','','| Package / version | License metadata |','| --- | --- |')
foreach($id in @($packages.Keys|Sort-Object)){$notices+='| '+$id+' | '+$packages[$id].Replace('|','\|')+' |'}
$notices|Set-Content -LiteralPath (Join-Path $package 'THIRD-PARTY-NOTICES.md') -Encoding utf8
$entry=Join-Path $package 'Unpacker.exe'
$fileVersion=[Diagnostics.FileVersionInfo]::GetVersionInfo($entry).FileVersion
if($fileVersion -ne "$Version.0"){throw "Unexpected executable version: $fileVersion"}
foreach($worker in @('worker/Unpacker.Worker.exe','worker/modern/Unpacker.ModernWorker.exe')){
    $path=Join-Path $package $worker
    if([Diagnostics.FileVersionInfo]::GetVersionInfo($path).FileVersion -ne "$Version.0"){throw "Worker version mismatch: $worker"}
}
# Portable PDB document names can store absolute paths as separate blobs.
# Inspect decoded names rather than searching the binary for a full path.
$symbolCount=0
foreach($symbol in Get-ChildItem -LiteralPath $package -Recurse -File -Filter '*.pdb'){
    $stream=[IO.File]::OpenRead($symbol.FullName)
    $provider=$null
    try{
        $provider=[System.Reflection.Metadata.MetadataReaderProvider]::FromPortablePdbStream($stream)
        $metadata=$provider.GetMetadataReader()
        foreach($handle in $metadata.Documents){
            $document=$metadata.GetString($metadata.GetDocument($handle).Name)
            if($document -match '^(?:[A-Za-z]:[\\/]|[\\/]{2}|/(?!_/|_packages/))'){
                throw "A release symbol contains an unmapped source path: $($symbol.Name)"
            }
        }
        $symbolCount++
    }
    finally{
        if($provider){$provider.Dispose()}
        $stream.Dispose()
    }
}
& $entry analyzer $entry *> (Join-Path $run 'analyzer.json')
if($LASTEXITCODE -ne 0){throw 'Packaged analyzer check failed.'}
$null=Get-Content -LiteralPath (Join-Path $run 'analyzer.json') -Raw|ConvertFrom-Json
Remove-ReleaseTemporary (Join-Path $package 'temp')
[ordered]@{Version=$Version;Commit=$commit;Sdk=$sdk;BuiltAtUtc=[DateTime]::UtcNow.ToString('o');EntryPoint='Unpacker.exe';FileVersion=$fileVersion;RuntimeDependent=$true;AnalyzerCheck='passed'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $package 'release.json') -Encoding utf8
$manifest=@(Get-ChildItem -LiteralPath $package -Recurse -File|Sort-Object FullName|ForEach-Object {
    [ordered]@{File=[IO.Path]::GetRelativePath($package,$_.FullName).Replace('\','/');Bytes=$_.Length;Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
})
ConvertTo-Json -InputObject $manifest -Depth 5|Set-Content -LiteralPath (Join-Path $package 'manifest.json') -Encoding utf8
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($stage,$zip,[IO.Compression.CompressionLevel]::Optimal,$false)
Expand-Archive -LiteralPath $zip -DestinationPath $verify
$expanded=Join-Path $verify $name
foreach($item in $manifest){
    $file=Join-Path $expanded $item.File
    if((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $item.Sha256){throw "Archive hash verification failed: $($item.File)"}
}
if(@(Get-ChildItem -LiteralPath $expanded -Recurse -File).Count -ne $manifest.Count+1){throw 'Archive file count mismatch.'}
$hash=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $name-win.zip"|Set-Content -LiteralPath (Join-Path $output "$name-win.zip.sha256") -Encoding ascii
[ordered]@{Version=$Version;Commit=$commit;Archive=$zip;Sha256=$hash;Bytes=(Get-Item -LiteralPath $zip).Length;VerifiedFiles=$manifest.Count;VerifiedSymbols=$symbolCount;Checks='Packaged analyzer, symbol paths and archive hashes';AuditDirectory=$run}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $run 'verification.json') -Encoding utf8
foreach($path in @($source,$stage,$verify)){Remove-ReleaseTemporary $path}
Remove-ReleaseTemporary $archive
Write-Output "PASS: $zip"
Write-Output "SHA256: $hash"
Write-Output "Build/package evidence: $run"
