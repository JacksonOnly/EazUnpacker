# EazUnpacker

A command-line unpacker and deobfuscator for **Eazfuscator.NET managed assemblies**. Recover analyzable IL, generate readable identifiers, and optionally export a C# project.

[简体中文](README.md) · **English** · **v1.4.2** · [Changelog](CHANGELOG.md)

[Quick start](#quick-start) · [Features](#features) · [String editing](#edit-encrypted-strings-in-place) · [Options](#options-and-exit-codes) · [Development](#development-and-build)

> Recovery uses metadata and IL semantics. Supported protections depend on the recovery report; arbitrary assemblies are not guaranteed to be fully restored.

## Features

| Area | Capabilities |
| --- | --- |
| Strings and resources | Recover supported strings and resources; export identity-checked embedded dependencies beside the output using assembly names; edit Eaz encrypted strings without unpacking |
| Devirtualization | Discover VM formats and call sites; recover supported instructions, signatures and exception regions; retain originals on failure |
| Inlining and proxies | Recover multiple VM sites per host; support constrained `ref` write-back; bypass transparent proxy chains and inline bounded, pure integer leaves |
| Control flow | Fold proven integer/enum predicates, simplify switch dispatch and jump chains, propagate constants across unique predecessors, remove unreachable IL and unused local stores |
| Readable symbols | Generate role-, base-type- and entry-point-aware names, shorten parameters, emit name maps and Portable PDBs; retain type, namespace and member names in markup-bearing modules to preserve bindings |
| Key reporting | Log verified keys with tokens and input namespace/type/method identities; retain structured records |
| Optional source export | Export a C# project and string index with ILSpy, then attempt a rebuild |
| Optional CLR validation | Prepare recovered hosts, inline adapters and access bridges; **disabled by default** |
| Protection cleanup | After full VM recovery or when no VM is detected, remove unreferenced VM/decoder code and replaced resources; retain referenced or unproven content |

## Quick start

### 1. Extract the complete release

Extract `EazUnpacker-v1.4.2-win.zip` and keep every subdirectory, including `worker\modern`. Run `Unpacker.exe`; copying the EXE alone is not sufficient.

- **Runtime**: Windows and .NET Framework 4.8. Modern .NET targets also need a suitable .NET Desktop Runtime. The modern worker targets .NET 8 and can roll forward to installed newer major versions.
- **Permissions**: use a short, writable directory; the tool creates `temp` beside its executable. Framework loaders or third-party tools can still encounter Windows long-path limits.
- **SDK**: not required for ordinary recovery. Rebuilding C# needs a .NET SDK and the target project's references. See [development](#development-and-build) to build the tool itself.

### 2. Run a command

Open PowerShell in the extracted directory:

```powershell
# Default: recover IL; no CLR preparation check and no source export
.\Unpacker.exe unpack ".\input\input.dll" ".\output\input_unpacked.dll"

# Explicitly enable CLR validation
.\Unpacker.exe unpack ".\input\input.dll" ".\output\input_unpacked.dll" --validate-clr

# Export/rebuild C# and also validate recovered/rebuilt methods
.\Unpacker.exe unpack ".\input\input.exe" ".\output\input_unpacked.exe" --export-source --validate-clr

# Static metadata analysis; stdout is JSON
.\Unpacker.exe analyzer ".\input\input.dll"
```

### 3. Inspect the result

The console reports the output file, diagnostic directory and final counts. Check the exit code first, then inspect `result.json` in that run's directory. A check that did not run has not passed.

Input and output must differ. Available recovered assemblies are published even when later stages are incomplete; reports retain the partial status. Deploy generated Framework EXE `.config` files alongside their EXEs. DLLs remain dependent on their host and dependencies.

Embedded managed dependencies are named from their assembly identities, not obfuscated resource names. Dependencies are placed before the main output; conflicting existing files stop publication without being overwritten. Only resources replaced by external files and protection code with no business references are removed. Unrestored VM code and unknown dynamic loaders remain intact.

## Edit encrypted strings in place

```powershell
.\Unpacker.exe strings ".\local\input.exe"
.\Unpacker.exe strings apply ".\local\input.exe"
# Or replace the original and keep a .bak backup
.\Unpacker.exe apply ".\local\input.exe" --in-place
```

Export and apply use `input.exe.strings.json` beside the input by default; you can also specify a catalog path. Apply writes `input.edited.exe` unless you select another output or use `--in-place`. Edit only the `text` fields. You can remove entries you do not want to change. The catalog is bound to the exported binary; export again before editing a modified file. Keep the decrypted catalog local.

Supports statically identifiable embedded string tables in managed PE files. The editor does not run or unpack the target. It can shorten, clear, or lengthen strings. If an edit does not fit the original slot, the editor rebuilds the resource and adds an offset map to the original decoder, preserving string IDs and call sites. Each encoded replacement is limited to 1 MiB. The editor verifies by decrypting the result and writes no partial output. Editing invalidates existing digital signatures.

## Options and exit codes

| Option | Default | Effect |
| --- | --- | --- |
| `--export-source` | Off | Export a C# project and string index, then attempt compilation |
| `--validate-clr` | Off | Prepare recovered IL in the CLR; also validate rebuilt methods when exporting source |

Options may appear before or after paths. Unknown or duplicate options fail. Optional stages that were not requested do not count as recovery failures; **not checked does not mean passed**.

| Code | Meaning |
| --- | --- |
| `0` | Requested stages completed |
| `2` | Output is available, but recovery or a requested optional stage is incomplete |
| `1` | Invalid arguments, input errors or processing errors |

### Environment variables

| Variable | Purpose |
| --- | --- |
| `UNPACKER_DEPENDENCY_PATHS` | Additional absolute dependency directories, separated by `;` on Windows |
| `UNPACKER_VM_VERBOSE=1` | More mapping information |
| `UNPACKER_VM_DEBUG=1` | Per-method/instruction diagnostics |
| `UNPACKER_VM_KEY_SEARCH_LIMIT` | Bounded integer search count; default `65536`, `0` disables it, maximum ten million |
| `UNPACKER_VM_KEY_SEARCH_SECONDS` | Module-wide integer fallback time budget; default `20` seconds, at most `5` per verifier, `0` disables it, maximum `120` |
| `UNPACKER_VM_INT32_KEYS` | Comma-separated integer candidates; original verification remains mandatory |
| `UNPACKER_VM_STRING_KEYS` | Explicit string candidates as a JSON array; original verification remains mandatory |
| `UNPACKER_VM_KEY_ASSET_PATHS` | Additional key resource files or directories, separated by `;` on Windows; supports managed assemblies, `.resources` and `.baml` |
| `UNPACKER_VM_USE_KEY_CACHE=1` | Permit explicitly supplied historical candidate cache |
| `UNPACKER_VM_KEY_CACHE_PATH` | Candidate cache path; no preset key table is bundled or read by default |

External-resource string key candidates are also read from the input directory and declared dependency directories, without recursive scanning. Assets are read as data under file/count limits; every candidate must pass the original verifier. Supply the resource assets when they are not part of the input. Missing keys preserve the original method; verification is not bypassed and no program-specific keys are bundled.

## Temporary files and outputs

All temporary work lives in **`temp` beside `Unpacker.exe`**. This is the executable directory, not the shell's current working directory.

```text
Unpacker.exe
worker/
  Unpacker.Worker.exe
  modern/
temp/
  work/<output-path-hash>/
    latest.json
    run-<timestamp>-<unique-id>/
      result.json
      progress.log
      ...
  analysis-<unique-id>/      # removed after analysis
```

The main program and packaged workers share this root. Child `TEMP` / `TMP` variables point here too. The installation directory must be writable; failures are reported instead of silently falling back elsewhere. Diagnostics, requested source and rebuilt outputs remain in their run directories. Clean `temp` only after processing has stopped.

## Dependencies and licenses

The combined project is [GPL-3.0](LICENSE). Third-party components retain their own licenses. See [NOTICE](NOTICE) for source origins, pinned baselines and local modifications.

### Vendored source

| Component | Role | License |
| --- | --- | --- |
| [EazFixer](src/ThirdParty/EazFixer) | String, resource and embedded-assembly recovery | [MIT](src/ThirdParty/EazFixer/LICENSE) |
| [EazyDevirt](src/ThirdParty/EazyDevirt) | VM discovery, decoding and IL recovery | [GPL-3.0](src/ThirdParty/EazyDevirt/LICENSE) |
| [Echo](src/ThirdParty/Echo) | CIL analysis and emulation infrastructure | [LGPL-3.0](src/ThirdParty/Echo/LICENSE.md) |

### Main NuGet references

| Package | Pinned version | Role |
| --- | --- | --- |
| dnlib | 4.5.0 | Metadata, IL and PDB rewriting |
| AsmResolver.DotNet | 6.0.0-beta.4 | VM backend PE/metadata and CIL generation |
| Lib.Harmony | 2.4.2 | Runtime adaptation in isolated decoder workers |
| BouncyCastle.Cryptography | 2.5.1 | VM encrypted-stream support |
| ICSharpCode.Decompiler | 11.1.0.9782 | ILSpy decompilation and project export |
| Newtonsoft.Json | 13.0.3 | Reports and progress serialization |
| System.Memory | 4.6.3 (main project) | Framework compatibility |

Echo also keeps upstream references such as `System.Collections.Immutable` and `Nullable`. Project files, NuGet metadata and included license files are authoritative for the complete dependency graph and licenses. These are pinned versions, not a latest-version list.

## Development and build

Run from the repository root. Building requires an SDK that supports `.slnx` and .NET Framework 4.8 development references. The .NET 10 SDK can be used to build this release.

```powershell
dotnet build Unpacker.slnx -c Release
```

The entry point is `src\bin\Release\net48\Unpacker.exe`. The release script builds a committed snapshot and excludes local inputs, caches and temporary work:

```powershell
pwsh -File .\scripts\Build-Release.ps1
```
