# umadump 2.0

Runtime memory reader and data exporter for **Uma Musume Pretty Derby** (x64 IL2CPP build).

Resolves live game objects from either a running process or a prepared full-memory
minidump, validates wrapper class layouts against `global-metadata.dat`, and exports
structured JSON data.

> **Python requirement:** This project requires **Python 3.14+**.

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

- Additional data points in the exports that are not available through the API, will be exposed through "extra_data"
  fields in the JSON output, so they can be used by downstream tools without breaking existing fields.

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
| `game_structs/`        | Game-specific ctypes wrappers (`WorkDataManager`, `WorkSkillData`, …)             |
| `schema_validation.py` | Schema and runtime validation framework (see below)                               |

---

## Output JSON contract

[`output_validation.jq`](output_validation.jq) is the public jq normalization
contract for comparing selected API payloads with umadump exports. It records
intentional placeholders, omissions, extensions, and ordering normalization.
Each section names the API source, dump file, and filters to apply to both sides.

The contract works directly with jq; no separate validator is required. API entry
points consume the complete decoded response envelope. Export entry points consume
the dump itself; exports needing no normalization use `pass_through`. For example:

```sh
jq -L . 'include "output_validation"; career_load_api' response.json
jq -L . 'include "output_validation"; pass_through' turn_024_010.json
```

Use files representing the same observation. The contract does not select matching
captures or perform the comparison.

## Career observations

The career extractor records active state in the shape of a load API response
after save-and-exit. Logs and event summaries are proprietary companion formats,
not part of that API payload. The event summary is derived exclusively from the
full log artifact and retains headings, selections, stored choice effects and result
effects without story dialogue.

Start daemon mode before beginning a career and leave it running through
finalization for the most complete record:

Archives are written to `career_data/<career identity>/`, with
`single_mode_load_common` and the applicable scenario dataset in each snapshot.
No network capture or save-and-exit routine is required; events and race phases
can produce observations as well as the training screen. Intentional placeholders
are documented in the output contract.

### Archive files

- `manifest.json`: persistent identity and archive description; existing
  manifests are checked, never rewritten.
- `turns/turn_###_###.json`: API-shaped load data. The first observation is `_000`;
  a changed payload gets the next revision. Repeated identical observations do
  not create another file. Earlier evidence remains immutable.
- `log.json`: reconciled dialogue, selected choices, result text, and heading-only
  groups. Separate `choice_observations` retain the API-shaped event metadata and
  `choice_reward_array` from its matching reward cache, without altering the raw
  `entries`. Rewards describe possible choice effects, not the selected outcome.
  Unchosen option text and button order are not captured.
- `events.json`: a projection of those entries and observations, without story
  dialogue. Replayed events remain separate occurrences; choice observations
  attach only to the current log heading, not to older matching titles.
- `veteran.json`: optional finalized character attachment.

Choice effects are captured when the client has populated an event-matched cache.
Each cache generation is retained once at the current observed log heading; this
does not establish when a choice box was visible. Unavailable or replaced caches
can be missed between polls.

Polling can miss short-lived states, and starting midway through a career cannot
recover earlier turns or discarded dialogue. The game's log buffer is bounded
and is not restored by reloading a career. Newly observed entries record the turn
and playing-state enum name. Keep the dumper running through finalization for a
chance to capture the matching `veteran.json` attachment.

## Independent Training (Idle Mode)

Independent Training uses separate files under `idle_single_mode/`, containing
single career report and, if available, the finalized veteran data.

## Trophy exports

Login-only trophies are written to `trophy_data_limited.json`. Open the Trophy
screen to populate race IDs and win counts for `trophy_data.json`. Both use the
same JSON shape; a limited or incomplete capture does not overwrite the detailed
file.

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

Enums use the same registration point, with one storage declaration per enum:

```python
@register_enum("Gallop::RaceDefine.RunningStyle", storage_type=c_uint8)
class RunningStyle(SafeIntEnum):
    None_ = 0
    Nige = 1
    # ...


class RaceFields(CStructureDataclass):
    runningStyle: C_Enum[RunningStyle]
    encryptedState: C_EnumIn[RunningStyle, ObscuredInt]
```

`C_Enum[E]` has the exact registered ctypes width in memory and reads as `E`.
`C_EnumIn[E, S]` preserves the outer storage `S` while recording its enum
semantics for validation. Startup validation checks enum members, `value__`
storage, and every direct enum field's reflected typedef; it also warns when a
matched numeric field is actually an unbound IL2CPP enum.

The enum read conversion is installed dynamically after ctypes classes are
created. This keeps the source-level field surface strict, so MyPy and
Protocols still reject undeclared fields.

Call `validate_registered_schema(resolver)` once after the resolver is ready.

---

## Metadata path

Auto-derived from the game executable:

```
<exe_dir>/<ExeName>_Data/il2cpp_data/Metadata/global-metadata.dat
```

Override with `--metadata-path` when using a minidump from a different machine.

---

## Usage

Grab latest release and just start it up - it'll run once and ask you if you want to rerun or enable a background
monitoring daemon.

Or you can use provided utility flags and minidump development modes. When running from source, no packages are
required,
albeit 3.14+ Python version is required. For Minidump driven development, install optional `minidump` package.

```powershell
# Live mode (attaches to running game process)
python main.py

# Live mode, run once and exit
python main.py --rerun-mode once

# Live daemon mode, polling every 2 seconds and writing changed outputs
python main.py --rerun-mode daemon --poll-interval 2

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
