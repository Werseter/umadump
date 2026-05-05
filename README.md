# umadump 2.0

Runtime memory reader and data exporter for **Uma Musume Pretty Derby** (x64 IL2CPP build).

Resolves live game objects from either a running process or a prepared full-memory
minidump, validates wrapper class layouts against `global-metadata.dat`, and exports
structured JSON data.

---

## How is it different from previous tooling?

- Before, the data extraction was based on catching a cached API network request, requiring specific timing and was
  prone to cache invalidation. We are now directly reading the game memory, which is more robust and works regardless of
  caching.
- The new tool is built around a flexible schema validation system that cross-checks declared wrapper class layouts
  against the full inheritance chain in metadata, catching any discrepancies at startup. Additionally, runtime guards
  verify object types on every access, preventing stale pointer dereferences or wrong-type casts from causing silent
  data corruption.

- Note: This means some data that was previously accessible through the API may not be available in the memory reader if
  it is not present in
  the metadata or if the wrapper class is not properly defined and validated. However, this trade-off provides a much
  more robust and maintainable foundation for future data extraction efforts.

  Besides, I don't think those missing data points are critical for the current use cases.

## Why?

- Support cards are only provided at login, meaning legacy approach had very low chance of success. This led to that and
  we're here now.
- It is overengineered for the task at hand, but it was a fun project to build and provides a solid foundation for
  future memory-based tools or mods.
- It allows us to export more data than just the API responses, including internal game state that may not be exposed
  through the API at all.
- It is more robust to game updates, as it relies on metadata validation rather than brittle pattern scans or cache
  timings. In case of a game update that changes the memory layout, the schema validation will catch any discrepancies
  at startup, allowing for a quicker fix.

## Files

| File                   | Purpose                                                                           |
|------------------------|-----------------------------------------------------------------------------------|
| `main.py`              | Entry point — wires memory backend, validation, and data export                   |
| `memory.py`            | Live-process and minidump `MemoryReader` implementations                          |
| `il2cpp_structs.py`    | IL2CPP ctypes struct definitions (metadata + runtime layouts, v31)                |
| `il2cpp_utils.py`      | `Il2CppResolutionManager` — type/field lookup and runtime type pointer resolution |
| `ctypes_utils.py`      | ctypes helpers: `CStructureDataclass`, `C_Ptr`, typed array, integer wrappers     |
| `game_structs.py`      | Game-specific ctypes wrappers (`WorkDataManager`, `WorkSkillData`, …)             |
| `schema_validation.py` | Schema and runtime validation framework (see below)                               |

---

## What it does

1. Opens a memory backend (live process or minidump file).
2. Locates `GameAssembly.dll` base address and size.
3. Scans for `MetadataRegistration` via pattern scan + pointer-array validation.
4. Parses required sections from `global-metadata.dat`:
    - strings, type definitions, field definitions, unresolved-call range count.
5. Builds a runtime type-pointer resolution context from `MetadataRegistration`.
6. **Schema validation** — for every registered wrapper class, cross-checks declared
   ctypes field names and byte offsets against the full *base-to-leaf* inheritance
   chain in metadata (so subclasses that inherit all fields, like
   `Gallop::WorkSkillData.AcquiredSkill`, are validated correctly).
7. **Runtime validation** — live object access guards verify the `typeMetadataHandle`
   of each IL2CPP object before any field read, catching stale pointers or wrong-type
   casts at the point of access.
8. Resolves game singletons and exports structured data to JSON.

---

## Schema & runtime validation

Two decorator functions are provided in `schema_validation.py`:

```python
@register_schema_validatable("Gallop::WorkSkillData.AcquiredSkill")
class AcquiredSkillFields(CStructureDataclass):
    ...


@register_runtime_validatable("Gallop::WorkDataManager")
class WorkDataManagerWrapper(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    ...
```

- `@register_schema_validatable` — metadata cross-check only (startup).
- `@register_runtime_validatable` — metadata cross-check **plus** per-access
  `typeMetadataHandle` guard installed on `__getattribute__`.

Call `validate_registered_classes(resolver)` once after the resolver is ready.

---

## Metadata path

Auto-derived from the game executable:

```
<exe_dir>/<ExeName>_Data/il2cpp_data/Metadata/global-metadata.dat
```

Override with `--metadata-path` when using a minidump from a different machine.

---

## Usage

```powershell
# Live mode (attaches to running game process)
python main.py

# Dev mode from full-memory minidump
python main.py --minidump "D:\path\to\dump.dmp" --metadata-path "D:\path\to\global-metadata.dat"

# Run schema validation only, then exit
python main.py --minidump "D:\path\to\dump.dmp" --validate-only

# Skip the startup GitHub release lookup
python main.py --no-update-check
```

---

## Versioning & update notifications

- The current build version is embedded in `update_check.py` as `CURRENT_VERSION` and is
  shown at startup.
- On normal startup, `main.py` performs a short best-effort call to the GitHub Releases
  API for [`Werseter/umadump`](https://github.com/Werseter/umadump/releases).
- Stable builds check for newer stable releases. Prerelease builds (for example
  `2.0.0-alpha`) also consider newer prerelease tags such as beta/rc builds and the final
  stable release.
- If a newer applicable release tag is available, the tool prints the release page link
  and, for a bundled executable build, prefers a direct `.exe` asset link when one exists.
- Network/API failures do **not** stop the dump process; the check is purely informative.

---

## TODO

- Add more wrapper classes and exports as needed.

## Legacy dumper

The old dumper is still available in the `legacy` branch, but it is no longer maintained.

## Is this bannable?

The program accesses the game memory. Currently, the game does not have any tools to intercept this kind of scan.
However, using this tool is at your own risk. The author is not responsible for any ban or penalty you may receive from
using it.
