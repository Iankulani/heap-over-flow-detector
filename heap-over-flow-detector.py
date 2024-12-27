# -*- coding: utf-8 -*-
"""
Created on Mon Oct 21 20:39:25 2024

@author: IAN CARTER KULANI

"""

import re

def detect_heap_operations(line):
    """Detect potential heap-related operations like malloc, free, and memory writes."""
    # Looking for memory allocation functions (malloc, calloc) and potential heap operations
    heap_patterns = [
        r"\bmalloc\b",  # malloc call, allocating memory
        r"\bcalloc\b",  # calloc call, allocating memory
        r"\bfree\b",    # free call, deallocating memory
        r"\bstr\b",     # storing to memory (might be an unsafe memory write)
        r"\bmov\b",     # potentially moving data to an unvalidated buffer
        r"\bpush\b",    # pushing data to the stack might be part of buffer manipulation
        r"\bsub\b",     # adjusting stack pointer, could be related to buffer management
        r"\badd\b",     # adding to stack pointer, similar to sub
        r"\bcmp\b",     # comparing data, might involve buffer size checks
    ]
    
    for pattern in heap_patterns:
        if re.search(pattern, line):
            return True
    return False

def detect_unbounded_memory_write(line, memory_size_pattern=r"\bsub\s+\$(\d+),\s+%rsp"):
    """Detect potential unbounded writes to memory."""
    # Searching for a memory write (e.g., unbounded memory access)
    if re.search(memory_size_pattern, line):
        return True
    return False

def detect_heap_overflow(file_path):
    """Detect heap overflow in an assembly source file."""
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    suspicious_operations = []
    heap_related_lines = []
    
    for i, line in enumerate(lines):
        line = line.strip()
        
        # Check if the line contains heap-related operations (e.g., malloc, free, buffer writes)
        if detect_heap_operations(line):
            heap_related_lines.append((i + 1, line))  # Save line number and content
        
        # Look for patterns of potential unbounded memory writes
        if detect_unbounded_memory_write(line):
            suspicious_operations.append((i + 1, line))  # Save line number and content
    
    return heap_related_lines, suspicious_operations

def main():
    """Main function to prompt user input and analyze the assembly file."""
    file_path = input("Enter the path to the assembly source file (.s): ")
    
    try:
        heap_related_lines, suspicious_operations = detect_heap_overflow(file_path)
        
        if heap_related_lines:
            print("\nPotential heap-related operations detected:")
            for line_num, line in heap_related_lines:
                print(f"Line {line_num}: {line}")
        
        if suspicious_operations:
            print("\nSuspicious unbounded memory write detected (possible overflow):")
            for line_num, line in suspicious_operations:
                print(f"Line {line_num}: {line}")
        
        if not heap_related_lines and not suspicious_operations:
            print("No heap overflow-related issues detected.")
    
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
