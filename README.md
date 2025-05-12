# Memory Scanner and Modifier

A Python-based memory scanning and modification tool. This application allows you to scan for specific values in memory, modify them, and freeze them to maintain their state. The tool includes a simple GUI for ease of use.

## Features

- **Process Selection:** Choose the target process for scanning and modification.  
- **Initial Scan:** Scan for specific values in memory with multiple encoding options.  
- **Address List:** View and manage a list of found addresses.  
- **Next Scan:** Narrow down the search by rescanning found addresses.
- **Value Editing:** Modify values in memory directly.  
- **Value Freezing:** Freeze specific memory addresses to maintain a constant value.  

## Usage

1. Launch the application.  
2. Select a process to scan.  
3. Enter the value to search for and start the initial scan.  
4. Refine the search by changing the value in the process, then scanning for the updated value using the **Next Scan** option.  
5. Modify, freeze, or unfreeze values from the address list.  
