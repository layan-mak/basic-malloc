# basic-malloc
Basic implementation of malloc, free, calloc, and realloc, written in C.

About the implementation:
- Every block has a **metadata** structure.
- A global pointer to a list (by size) that will contain all the data sectors, the list is used to search for free spaces upon allocation requests, instead of increasing the program break and enlarging the heap unnecessarily.
- **Internal fragmentation avoidance**: The data sectors are stored in a sorted list (by size), and allocations use the memory region with the minimal size that can fit the memory allocation. In addition, if a pre-allocated  block is reused and is large enough, the block is into two smaller blocks with two separate meta-data structs
- Use of mmap instead of sbrk for very large allocations.
- Safety and security: Use of **cookies** to check if the metadata of memory blocks have changed.
