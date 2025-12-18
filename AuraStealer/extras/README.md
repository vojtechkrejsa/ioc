# AuraStealer Scripts

This folder contains scripts for analyzing AuraStealer samples, as well as an example data-stealing configuration.

## Files

### AuraStealer configuration extractor (`aurastealer_config_extractor.py`)
A Python script to decrypt and extract the configuration from AuraStealer binaries.

**Usage:**

For a single sample:
`python aurastealer_config_extractor.py -s <path_to_sample>`

For a directory of samples:
`python aurastealer_config_extractor.py -d <path_to_directory>`

**Parameters:**
- `-s`: Path to a single sample file.
- `-d`: Path to a directory containing sample files.

### IDA Pro script to mark variables as const (`aurastealer_mark_as_const.py`)
An IDAPython script used to bulk-define variables as `const __int32`.

**How to use:**
1. Open the script in IDA as a script (File -> Script Command).
2. Edit the `start` and `end` variables with the memory address range you want to process (e.g., `start = 0x00401000`, `end = 0x00402000`).
3. Run the script within IDA Pro.

### IDA Pro script to decrypt AuraStealer strings (`aurastealer_decrypt_strings.py`)
A script that uses the Unicorn Engine to emulate execution paths and decrypt AuraStealer strings.

**Basic usage information:**
- The script is designed to be run from IDA as a script (File -> Script Command).
- The function used for decryption is selected based on the current cursor position.
- **The script assumes that the boundaries of the given function are correctly defined** (the emulation is terminated if an emulated instruction lies outside these boundaries)

### AuraStealer data collection configuration (`aurastealer_config.json`)
An example AuraStealer data-stealing configuration.