#include <unistd.h>
#include <cstring>
#include <sys/mman.h>
#include <math.h>
#define MAX_SIZE 100000000   //1e8B
#define MMAP_MIN_SIZE 131072 //128KB
#define MIN_SPLIT_SIZE 128   //128B

struct MallocMetaData 
{
    int cookie;
	size_t size; //size of block without size of metadata
	bool is_free;
	void* block_start_address;
	MallocMetaData* next;
	MallocMetaData* prev;
};

MallocMetaData* MetaHead = nullptr; //global pointer to fist node of metadata (start of heap) 

int cookie = rand();

size_t mmap_allocated_bytes;
size_t mmap_allocated_blocks;

/******************************* FUNCTIONS DECLARATIONS *********************************/


size_t _num_free_bytes();

size_t _num_allocated_blocks();

size_t _num_allocated_bytes();

size_t _num_free_blocks();

size_t _size_meta_data();

size_t _num_meta_data_bytes();

void* smalloc(size_t size);

void* scalloc(size_t num, size_t size);

void sfree(void* p);

void* srealloc(void* oldp, size_t size);

/****************************** OUR HELPER FUNCTIONS DECLARATIONS ***************************/

MallocMetaData* find_meta_from_block_address(void* block_address);

/* Helper function for smalloc:
 * if there is a free block: this function returns the smallest one that can fit the new size (its metadata)
 * if there is no free block that fits the new size, this function returns NULL
 * */
MallocMetaData* find_suitable_meta(size_t size);

//helper function for adding a node. (containing metadata)
void add_in_between(MallocMetaData* prev, MallocMetaData* next, MallocMetaData* new_meta);

void add_to_sorted_meta_list(MallocMetaData* new_meta);

/*
 * we remove this meta node only in order to add its memory space to another adjacent meta block!
--> so there will not be any "wasted meta".. --> can use arithmetic operations with meta sizes and block start addresses..
 */
void detach_meta_node(MallocMetaData* to_remove);

/*
 * returns the block start address of the new block (could be newly allocated or reused)
assumes that allocation candidate is already free (doesn't check that)
* */
void* reuse_and_split_if_needed(MallocMetaData* allocation_candidate, size_t size);

/*
 * this functions allocates a new block in the HEAP and returns the new metaData
 * DOESN'T add to sorted list of metas!
 */
MallocMetaData* allocate_new_block(size_t size);

MallocMetaData* find_topmost_allocated_chunk();

/*
 * if the wilderness chunk is free this function enlarges it and returns its meta node
 * else: it returns null
 * new_size : is the requested size for the enlarged wilderness chunk. 
 * IT IS NOT THE DIFFERENCE BETWEEN THE WANTED SIZE AND THE CURRENT WILDERNESS SIZE!
 */
MallocMetaData* enlarge_wilderness_chunk(size_t new_size);

/*
 * returns upper meta (in terms of addresses and not sizes!)
 * maybe change everything to while loops and not arithmetic operations? ..
 * */
MallocMetaData* find_upper_meta(MallocMetaData* current_meta);

MallocMetaData* find_lower_meta(MallocMetaData* current_meta);


/*
 * merges with upper block
 * -- There's only one meta at the end of this function:
 * Current meta "eats" the upper meta
 * returns the MERGED meta
 * works only if upper block is free! adds the new merged meta to sorted list
 * */
MallocMetaData* merge_with_upper_block(MallocMetaData* current_meta);

/*
 * merges with lower block
 * -- There's only one meta at the end of this function:
 * Lower meta "eats" the upper meta
 * works only if lower block is free!
 * */
MallocMetaData* merge_with_lower_block(MallocMetaData* current_meta);

/*
 * lower meta eats current and upper meta
 * works only if upper and lower blocks are free!
 * */
MallocMetaData* merge_with_two_adjacent_blocks(MallocMetaData* current_meta);

void combine_adjacent_free_blocks(MallocMetaData* current_meta);

bool node_is_in_heap(MallocMetaData* meta);

void check_cookie(MallocMetaData* meta);

/*
* if lower meta is free, and the size of current meta and lower one are enough to use for allocation return true
* else return false
* */
bool check_size_combined_with_lower(MallocMetaData* current_meta, size_t size_to_allocate);

/*
 * if upper meta is free, and the size of current meta and upper one are enough to use for allocation return true
 * else return false
 * */
bool check_size_combined_with_upper(MallocMetaData* current_meta, size_t size_to_allocate);

/*
 * if upper and lower meta are free, and the size of current meta, upper one and lower one are enough to use for allocation return true
 * else return false
 * */
bool check_size_combined_with_upper_and_lower(MallocMetaData* current_meta, size_t size_to_allocate);

/*
 * Returns true if current meta is the wilderness, false otherwise
 * */
bool am_wilderness(MallocMetaData* current_meta);

bool lower_is_free(MallocMetaData* current_meta);

/****************************** HELPER FUNCTIONS IMPLEMENTATIONS ************************/

MallocMetaData* find_meta_from_block_address(void* block_address)
{
    size_t base = (size_t)block_address - _size_meta_data();
    MallocMetaData* meta = (MallocMetaData*)((void*)(base));
	return meta;
}


MallocMetaData* find_suitable_meta(size_t size)
{
    if(!MetaHead) return nullptr;
	MallocMetaData* current = MetaHead;
    check_cookie(current);
	if(current->is_free && current->size >= size) return current;
	while(current)
	{
        check_cookie(current);
		if(!current->next) return NULL;
		if(current->next->is_free && current->next->size >= size)
			return current->next;
		current = current->next;		
	}
	return current;
}

void add_in_between(MallocMetaData* prev, MallocMetaData* next, MallocMetaData* new_meta)
{
    check_cookie(new_meta);
    if(prev != nullptr)
    {
        check_cookie(prev);
        prev->next = new_meta;
    }
	new_meta->prev = prev;
	new_meta->next = next;
	if(next != nullptr)
	{
        check_cookie(next);
		next->prev = new_meta;
	}
}

void add_to_sorted_meta_list(MallocMetaData* new_meta)
{
	//if(!MetaHead) return;  //sure?
    if(!new_meta) return;
    check_cookie(new_meta);
    check_cookie(MetaHead);
    if(!MetaHead)
    {
		MetaHead = new_meta;
	}
	MallocMetaData* current = MetaHead;
	if(new_meta->size < current->size) //I want to be the first node
	{
        MetaHead = new_meta;
		new_meta->next = current;
		current->prev = new_meta;
		new_meta->prev = nullptr;
	}
	else //I'm not the first node
	{
        check_cookie(current->next);
		while(current->next && current->next->size < new_meta->size)
		{
            check_cookie(current);
            check_cookie(current->next);
			current = current->next;
		}
        check_cookie(current);
        check_cookie(current->next);
		if(current->next == nullptr) //reached the end of the list
		{
			add_in_between(current, current->next, new_meta);
		}
		else if(current->next && current->next->size > new_meta->size)
		{
			add_in_between(current, current->next, new_meta);
		}
		else if(current->next->size == new_meta->size)
		{
			while(current->next && current->next->size == new_meta->size && current->next->block_start_address < new_meta->block_start_address)
			{
                check_cookie(current);
                check_cookie(current->next);
				current = current->next;
			}
			add_in_between(current, current->next, new_meta);
		}
	}
}

void detach_meta_node(MallocMetaData* to_remove)
{
    if(!to_remove) return;
    check_cookie(to_remove);
    check_cookie(MetaHead);
    //if we want to remove the head:
    if(to_remove == MetaHead)
    {
        MetaHead = MetaHead->next;
        if(MetaHead)
        {
			MetaHead->prev = nullptr;
		}
        to_remove->prev = nullptr;
        to_remove->next = nullptr;
        return;
    }
    MallocMetaData* prev = to_remove->prev;
    MallocMetaData* next = to_remove->next;
    if(prev!=nullptr)
    {
        check_cookie(prev);
        prev->next = to_remove->next;
    }
    if(next != nullptr)
    {
        check_cookie(next);
        next->prev = prev;
    }
    to_remove->next = nullptr;
    to_remove->prev = nullptr;
}

void* reuse_and_split_if_needed(MallocMetaData* allocation_candidate, size_t size)
{
    void* address_to_return;
    check_cookie(allocation_candidate);
    if(allocation_candidate->size - size >= MIN_SPLIT_SIZE + _size_meta_data()) //if large enough ->> split!
    {
        size_t old_size = allocation_candidate->size;
        allocation_candidate->size = size;
        allocation_candidate->is_free = false;
        void* new_meta_address = (void*)((size_t)(allocation_candidate->block_start_address) + size);
        MallocMetaData* new_meta = (MallocMetaData*) new_meta_address;
        new_meta->is_free = true;
        new_meta->size = old_size - size - _size_meta_data();
        new_meta->block_start_address = (void*) ((size_t)new_meta_address + _size_meta_data());
        new_meta->cookie = cookie;
        add_to_sorted_meta_list(new_meta);
        //combine_adjacent_free_blocks(new_meta); //don't merge after splitting!
        address_to_return = allocation_candidate->block_start_address;
    }
    else //reuse, no need to split
    {
        allocation_candidate->is_free = false;
        address_to_return = allocation_candidate->block_start_address;
        //don't change size!
    }
    return address_to_return;
}

MallocMetaData* allocate_new_block(size_t size)
{
    void* sbrk_res = sbrk((intptr_t)(_size_meta_data() + size));
    if(sbrk_res == (void*)(-1))
    {
        return NULL;
    }
    MallocMetaData* new_meta = (MallocMetaData*) sbrk_res;
    new_meta->size = size;
    new_meta->block_start_address = (void*) (size_t(sbrk_res) + _size_meta_data());
    new_meta->is_free = false;
    new_meta->cookie = cookie;
    //add_to_sorted_meta_list(new_meta);
    return new_meta;
}

MallocMetaData* find_topmost_allocated_chunk()
{
    if(!MetaHead) return nullptr;
    check_cookie(MetaHead);
    MallocMetaData* current = MetaHead;
    MallocMetaData* wilderness = current;
    while(current)
    {
        check_cookie(current);
        size_t curr_address = (size_t)current->block_start_address;
        size_t max_address = (size_t)wilderness->block_start_address;
        if(curr_address > max_address)
        {
            wilderness = current;
        }
        current = current->next;
    }
    return wilderness;
}

MallocMetaData* enlarge_wilderness_chunk(size_t new_size)
{
    MallocMetaData* wilderness_meta = find_topmost_allocated_chunk();
    if(!wilderness_meta) return nullptr;
    check_cookie(wilderness_meta);
    if(!wilderness_meta->is_free) return nullptr;
    size_t size_to_add = new_size - wilderness_meta->size;
    void* sbrk_res = sbrk((intptr_t)size_to_add);
    if(sbrk_res == (void*)(-1))
    {
        return nullptr;
    }
    wilderness_meta->size = new_size;
    detach_meta_node(wilderness_meta);
    add_to_sorted_meta_list(wilderness_meta);
    return wilderness_meta;
}

MallocMetaData* find_upper_meta(MallocMetaData* current_meta)
{
    check_cookie(current_meta);
    MallocMetaData* upper_meta;
    void* upper_address = (void*)((size_t)(current_meta->block_start_address) + current_meta->size);
    void* program_break = sbrk(0);
    if(upper_address == program_break) //if this is the last meta
    {
        upper_meta = nullptr;
    }
    else
    {
        upper_meta = (MallocMetaData*)upper_address;
    }
    return upper_meta;
}

MallocMetaData* find_lower_meta(MallocMetaData* current_meta)
{
    if(!MetaHead) return nullptr;
    MallocMetaData*  current = MetaHead;
    check_cookie(MetaHead);
    check_cookie(current_meta);
    while(current)
    {
        if(find_upper_meta(current) == current_meta)  // == operand for this struct?? if not, compare by block addresses! CHECK DONE ! :) WORKS WELL.
        {
            return current;
        }
        current = current->next;
        check_cookie(current);
    }
    return nullptr;
}

MallocMetaData* merge_with_upper_block(MallocMetaData* current_meta)
{
    check_cookie(current_meta);
    MallocMetaData* upper_meta = find_upper_meta(current_meta);
    check_cookie(upper_meta);
    if(!upper_meta || !upper_meta->is_free) return nullptr;
    current_meta->size += upper_meta->size + _size_meta_data();
    detach_meta_node(upper_meta);
    detach_meta_node(current_meta);
    add_to_sorted_meta_list(current_meta);
    return current_meta;
}

MallocMetaData* merge_with_lower_block(MallocMetaData* current_meta)
{
    check_cookie(current_meta);
    MallocMetaData* lower_meta = find_lower_meta(current_meta);
    check_cookie(lower_meta);
    if(!lower_meta || !lower_meta->is_free) return nullptr;
    lower_meta->size += current_meta->size + _size_meta_data();
    detach_meta_node(current_meta);
    detach_meta_node(lower_meta);
    add_to_sorted_meta_list(lower_meta);
    return lower_meta;
}

MallocMetaData* merge_with_two_adjacent_blocks(MallocMetaData* current_meta)
{
    check_cookie(current_meta);
    MallocMetaData* lower_meta = find_lower_meta(current_meta);
    MallocMetaData* upper_meta = find_upper_meta(current_meta);
    if(!lower_meta || !upper_meta || !lower_meta->is_free || !upper_meta->is_free) return nullptr;
    check_cookie(lower_meta);
    check_cookie(upper_meta);
    lower_meta->size += current_meta->size + upper_meta->size + 2*_size_meta_data();
    detach_meta_node(current_meta);
    detach_meta_node(upper_meta);
    detach_meta_node(lower_meta);
    add_to_sorted_meta_list(lower_meta);
    return lower_meta;
}

void combine_adjacent_free_blocks(MallocMetaData* current_meta)
{
    check_cookie(current_meta);
    MallocMetaData* res = merge_with_two_adjacent_blocks(current_meta);
    if(res) return;
    res = merge_with_upper_block(current_meta);
    if(res) return;
    merge_with_lower_block(current_meta);
}

bool node_is_in_heap(MallocMetaData* meta)
{
    MallocMetaData* curr = MetaHead;
    check_cookie(MetaHead);
    while(curr)
    {
        check_cookie(curr);
        if(curr == meta)
        {
            return true;
        }
        curr = curr->next;
    }
    return false;
}

void check_cookie(MallocMetaData* meta)
{
    if(!meta) return;
    if(meta->cookie != cookie)
    {
        exit(0xdeadbeef);
    }
}

bool check_size_combined_with_lower(MallocMetaData* current_meta, size_t size_to_allocate)
{
	check_cookie(current_meta);
    MallocMetaData* lower_meta = find_lower_meta(current_meta);
    check_cookie(lower_meta);
    if(lower_meta && lower_meta->is_free && (current_meta->size + lower_meta->size + _size_meta_data() >= size_to_allocate))
    {
        return true;
    }
    return false;
}

bool check_size_combined_with_upper(MallocMetaData* current_meta, size_t size_to_allocate)
{
	check_cookie(current_meta);
    MallocMetaData* upper_meta = find_upper_meta(current_meta);
    check_cookie(upper_meta);
    if(upper_meta && upper_meta->is_free && (current_meta->size + upper_meta->size + _size_meta_data() >= size_to_allocate))
    {
        return true;
    }
    return false;
}

bool check_size_combined_with_upper_and_lower(MallocMetaData* current_meta, size_t size_to_allocate)
{
	check_cookie(current_meta);
    MallocMetaData* lower_meta = find_lower_meta(current_meta);
    MallocMetaData* upper_meta = find_upper_meta(current_meta);
    check_cookie(lower_meta);
    check_cookie(upper_meta);
    size_t combined_size = current_meta->size + upper_meta->size + lower_meta->size + 2 * _size_meta_data();
    if(lower_meta && upper_meta && lower_meta->is_free && upper_meta->is_free &&
       (combined_size >= size_to_allocate))
    {
        return true;
    }
    return false;
}

bool am_wilderness(MallocMetaData* current_meta)
{
    if(!current_meta) return false;
    check_cookie(current_meta);
    MallocMetaData* wilderness = find_topmost_allocated_chunk();
    check_cookie(wilderness);
    if(current_meta == wilderness) return true; //if we reached this point, lower is free for sure
    return false;
}

bool lower_is_free(MallocMetaData* current_meta)
{
    MallocMetaData* lower = find_lower_meta(current_meta);
    if(!lower || !lower->is_free) return false;
    return true;
}

/*******************************************************************************************/


size_t _num_free_bytes()
{
	size_t count = 0;
	MallocMetaData* tmp = MetaHead;
	while(tmp)
	{
        check_cookie(tmp);
		if(tmp->is_free) count += tmp->size;
		tmp = tmp->next;
	}
	return count;
}

size_t _num_allocated_blocks()
{
	size_t count = 0;
	MallocMetaData* tmp = MetaHead;
	while(tmp)
	{
        check_cookie(tmp);
		count++;
		tmp = tmp->next;
	}
    count += mmap_allocated_blocks;
	return count;
}

size_t _num_allocated_bytes()
{
	size_t count = 0;
	MallocMetaData* tmp = MetaHead;
	while(tmp)
	{
        check_cookie(tmp);
		count += tmp->size;
		tmp = tmp->next;
	}
    count += mmap_allocated_bytes;
	return count;
}

size_t _num_free_blocks()
{
    size_t count = 0;
    MallocMetaData* tmp = MetaHead;
    while(tmp)
    {
        check_cookie(tmp);
        if(tmp->is_free) count ++;
        tmp = tmp->next;
    }
    return count;
}

size_t _size_meta_data()
{
	return sizeof(MallocMetaData);
}

size_t _num_meta_data_bytes()
{
	return _size_meta_data() * _num_allocated_blocks();
}


void* smalloc(size_t size)
{
    if(size == 0 ||size > MAX_SIZE)
    {
        return nullptr;
    }
	
	if(size >= MMAP_MIN_SIZE) //big enough to add to map
    {
		void* mmap_res = mmap(NULL, size + _size_meta_data(), PROT_READ | PROT_WRITE,
							  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if(mmap_res == (void*)-1)
		{
			return nullptr;
		}
		MallocMetaData* new_meta = (MallocMetaData*) mmap_res;
		new_meta->is_free = false;
		new_meta->size = size;
		new_meta->block_start_address = (void*)((size_t)mmap_res + _size_meta_data());
		new_meta->prev = nullptr;
		new_meta->next = nullptr;
		mmap_allocated_bytes += size;
		mmap_allocated_blocks++;
		new_meta->cookie = cookie;
		return new_meta->block_start_address;
	}
	//work in heap
	
	if(MetaHead == NULL)       //first allocation
	{
		MetaHead = allocate_new_block(size);
		MetaHead->next = NULL;
		MetaHead->prev = NULL;
		return MetaHead->block_start_address;
	}
	
    //not the first allocation
    
	void* address_to_return;
	MallocMetaData* allocation_candidate = find_suitable_meta(size);
	
	if(allocation_candidate != NULL) //found a space to reuse!
	{
		address_to_return = reuse_and_split_if_needed(allocation_candidate, size);
	}
	
	else //need to allocate a new block!
	{
		MallocMetaData* free_wilderness_meta = enlarge_wilderness_chunk(size);
		if(free_wilderness_meta != nullptr)
		{
			free_wilderness_meta->is_free = false;
			address_to_return = free_wilderness_meta->block_start_address;
		}
		else
		{
			MallocMetaData* new_meta = allocate_new_block(size);
			add_to_sorted_meta_list(new_meta);
			address_to_return = new_meta->block_start_address;
		}
	}
	return address_to_return;
}

void* scalloc(size_t num, size_t size)
{
    size_t new_size = num*size;
    void* smalloc_res = smalloc(new_size);
    if(smalloc_res == NULL)
    {
        return NULL;
    }
    void* memset_res = std::memset(smalloc_res, 0, num*size);
    if(memset_res == nullptr)
    {
        return nullptr;   
    }
    return smalloc_res;
}

void sfree(void* p)
{
	if(!p) return;
	MallocMetaData* meta = find_meta_from_block_address(p);
    if(!(meta && !meta->is_free)) return;
    //check if memory mapped region or heap:
    if(!node_is_in_heap(meta)) //mmapped
    {
        size_t meta_size = meta->size;
        void* meta_address = (void*)((size_t)meta->block_start_address - _size_meta_data());
        munmap(meta_address, meta_size + _size_meta_data());
        mmap_allocated_bytes -= meta_size;
        mmap_allocated_blocks--;
    }
    else
    {
		if(!MetaHead) return;
        meta->is_free = true;
        combine_adjacent_free_blocks(meta);
    }
}

void* srealloc(void* oldp, size_t size)
{
	if(size > MAX_SIZE) return nullptr;
    if(!oldp)
    {
        return smalloc(size);
    }
	MallocMetaData* meta = find_meta_from_block_address(oldp);
    check_cookie(meta);
    bool in_heap = node_is_in_heap(meta);
    meta->is_free = true; 
    if(!in_heap) //mmapped region
    {
        if(meta->size == size)
        {
			meta->is_free = false;
            return oldp;
        }
		void* meta_address = (void*)((size_t)oldp - _size_meta_data());
		void* mmap_res = mmap(NULL, size + _size_meta_data(), PROT_READ | PROT_WRITE,
							  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if(mmap_res == (void*)-1)
		{
			return nullptr;
		}
		MallocMetaData* new_meta = (MallocMetaData*) mmap_res;
		new_meta->is_free = false;
		new_meta->size = size;
		new_meta->cookie = cookie;
		new_meta->next = nullptr;
		new_meta->prev = nullptr;
		new_meta->block_start_address = (void*)((size_t)mmap_res + _size_meta_data());
		mmap_allocated_bytes += size;
		size_t size_to_move = meta->size;
		if(size < meta->size)
		{
			size_to_move = size;
		}
		std::memmove(new_meta->block_start_address, meta->block_start_address, size_to_move); //check size - done
		mmap_allocated_bytes -= meta->size;
		munmap(meta_address, meta->size + _size_meta_data());
		return new_meta->block_start_address;
    }
    else         //in heap
    {
        bool merged_or_enlarged = false;
        if(size <= meta->size) //reuse same block
        {
			reuse_and_split_if_needed(meta, size);
			meta->is_free = false;
            return oldp;
        }
        MallocMetaData* meta_to_allocate; //here will be the new meta to use/ allocate in
        if(check_size_combined_with_lower(meta, size)) //check if lower block is enough
        {
            meta_to_allocate = merge_with_lower_block(meta); 
            /* we did merge meta with lower one but technically, the bytes in meta didn't change and its struct
            is still available (same address) only detached. So we can move from meta to lower (combined one)
            * */
            merged_or_enlarged = true;
        }
        else if(am_wilderness(meta) && lower_is_free(meta))
        {
            meta_to_allocate = merge_with_lower_block(meta); 
            meta_to_allocate = enlarge_wilderness_chunk(size);  
            merged_or_enlarged = true;
        }
        else if(am_wilderness(meta))
        {
            meta_to_allocate = enlarge_wilderness_chunk(size);
            merged_or_enlarged = true;
        }
        else if(check_size_combined_with_upper(meta, size))
        {
            meta_to_allocate = merge_with_upper_block(meta); //should return (current) meta
            merged_or_enlarged = true;
        }
        else if(check_size_combined_with_upper_and_lower(meta, size))
        {
            meta_to_allocate = merge_with_two_adjacent_blocks(meta);
            merged_or_enlarged = true;
        }
        else if(am_wilderness(find_upper_meta(meta)) && find_upper_meta(meta)->is_free)
        {	
            if(find_lower_meta(meta) && find_lower_meta(meta)->is_free)
            {
                meta_to_allocate = merge_with_two_adjacent_blocks(meta);
                meta_to_allocate = enlarge_wilderness_chunk(size);
            }
            else //can't merge with lower, so will only merge with upper (wilderness) and enlarge it
            {
                meta_to_allocate = merge_with_upper_block(meta);
                meta_to_allocate = enlarge_wilderness_chunk(size);
            }
            merged_or_enlarged = true;
        }
        if(merged_or_enlarged)
        {
			reuse_and_split_if_needed(meta_to_allocate, size);
			meta_to_allocate->is_free = false;
            std::memmove(meta_to_allocate->block_start_address, oldp, size);
            return meta_to_allocate->block_start_address;
        }
        else
        {
            //else: allocating new block/ reusing one without merging
            void* smalloc_res = smalloc(size);
            if(!smalloc_res)
            {
                return NULL;
            }
            std::memmove(smalloc_res, oldp, meta->size);
            sfree(oldp);
            return smalloc_res;
        }
    }
}
