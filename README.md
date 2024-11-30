# rogue

A Binary Ninja plugin for FINAL FANTASY XIV.

## Installation

- Clone this repository into `%AppData%/Binary Ninja/plugins`
- Install the required libraries from `requirements.txt` with `Install python3 module...` in the Command Palette
- (Optional) Build the `Rogue.Helper` executable for features that require game data

## Features

- `Rename executable`: Apply names from FFXIVClientStructs' data.yml
- `Import structs`: Import structs from FFXIVClientStructs' ffxiv_structs.yml
- `Comment log messages`: Adds comments to ShowLogMessage and whatnot

## TODO

- [x] Struct importing
- [ ] Excel getters
