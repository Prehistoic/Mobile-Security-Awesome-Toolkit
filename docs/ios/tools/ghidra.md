# Ghidra
- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
- [Tips \& Tricks](#tips--tricks)
  - [Search for Strings](#search-for-strings)

## Description

`Ghidra` is a software reverse engineering (SRE) framework created and maintained by the [National Security Agency Research Directorate](https://www.nsa.gov/). This framework includes a suite of full-featured, high-end software analysis tools that enable users to analyze compiled code on a variety of platforms including Windows, macOS, and Linux. 

Capabilities include disassembly, assembly, decompilation, graphing, and scripting, along with hundreds of other features. Ghidra supports a wide variety of processor instruction sets and executable formats and can be run in both user-interactive and automated modes. Users may also develop their own Ghidra extension components and/or scripts using Java or Python.

## Installation

- Prerequisites : JDK 21+
- Download [latest release](https://github.com/NationalSecurityAgency/ghidra/releases) from official Github
- Unzip and run `ghidraRun`

## Usage

- Launch Ghidra with `ghidraRun`
- Create a **New Project** (`File > New Project`)
- **Import the Binary**: `File > Import File` and select target file
  - For iOS, extract the main Mach-O executable from the IPA bundle
- **Analyze the Binary**: double-click the imported file to open the **Code Browser**, click **Yes** to run the initial auto-analysis

## Tips & Tricks

### Search for Strings
- Window > Defined Strings
- Filter for wanted string. Can use `Text Filter Options` button to use regexes