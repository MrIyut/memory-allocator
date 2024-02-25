// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include "osmem.h"
#include "string.h"
#include "../utils/block_meta.h"

#define PAGE_SIZE 4096
#define MMAP_THRESHOLD (128 * 1024)
#define ALLIGN_SIZE(size) ((size + 7) & (~7))
#define ERR_RET ((void *)-1)
#define SIZE_BLOCK_META (ALLIGN_SIZE(sizeof(struct block_meta)))

struct block_meta *mem_head;
int preallocated;

void *get_pointer_from_block_meta(struct block_meta *block)
{
	return (void *)((char *)block + SIZE_BLOCK_META);
}
struct block_meta *get_block_meta_from_pointer(void *ptr)
{
	return (struct block_meta *)((char *)ptr - SIZE_BLOCK_META);
}
struct block_meta *get_last_list_block(void)
{
	return mem_head != NULL ? mem_head->prev : NULL;
}
struct block_meta *get_last_heap_block(void)
{
	if (!mem_head)
		return NULL;

	struct block_meta *block = mem_head->prev;

	while (block && block->status == STATUS_MAPPED && block != mem_head)
		block = block->prev;
	return block->status == STATUS_MAPPED ? NULL : block;
}
void insert_list_right_of(struct block_meta *new_block, struct block_meta *block)
{
	if (!mem_head) {
		mem_head = new_block;
		mem_head->next = mem_head;
		mem_head->prev = mem_head;
		return;
	}

	struct block_meta *next = block->next;

	block->next = new_block;
	new_block->prev = block;
	new_block->next = next;
	next->prev = new_block;
}
void remove_from_list(struct block_meta *block)
{
	if (block->prev)
		block->prev->next = block->next;
	if (block->next)
		block->next->prev = block->prev;
	if (mem_head == block)
		mem_head = block->next == mem_head ? NULL : block->next;
	block->next = NULL;
	block->prev = NULL;
}
struct block_meta *create_block(size_t size, size_t check_size, size_t threshold)
{
	struct block_meta *block = NULL;

	if (check_size < threshold) {
		block = sbrk(0);
		void *p = sbrk(size + SIZE_BLOCK_META);

		DIE(p == ERR_RET, "sbrk failed");
		block->status = STATUS_ALLOC;
	} else {
		block = mmap(NULL, size + SIZE_BLOCK_META, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		DIE(block == MAP_FAILED, "mmap failed");
		block->status = STATUS_MAPPED;
	}

	block->size = size;
	block->prev = NULL;
	block->next = NULL;
	return block;
}
void coalesce_block(struct block_meta *block)
{
	if (block->status != STATUS_FREE)
		return;

	if (block->next && block->next->status == STATUS_FREE && block->next != mem_head) {
		block->size = block->size + block->next->size + SIZE_BLOCK_META;
		remove_from_list(block->next);
	}

	if (block->prev && block->prev->status == STATUS_FREE && block != mem_head) {
		block->prev->size = block->prev->size + block->size + SIZE_BLOCK_META;
		remove_from_list(block);
	}
}
void remodel_block(struct block_meta *block, size_t offset, size_t new_block_size)
{
	struct block_meta *new_block = (struct block_meta *)((char *)block + offset + SIZE_BLOCK_META);

	new_block->status = STATUS_FREE;
	new_block->size = new_block_size;
	insert_list_right_of(new_block, block);
	coalesce_block(new_block);
}
struct block_meta *split_block(struct block_meta *block, size_t size)
{
	size_t remaining_size = block->size - size;

	block->status = STATUS_ALLOC;
	if (remaining_size < 8 + SIZE_BLOCK_META)
		return block;
	remaining_size -= SIZE_BLOCK_META;
	block->size = size;
	remodel_block(block, size, remaining_size);

	return block;
}
struct block_meta *find_best_block(size_t size)
{
	if (!mem_head)
		return NULL;

	struct block_meta *best_block = NULL;
	size_t best_size = ~1;
	struct block_meta *block = mem_head;

	do {
		if (block->status != STATUS_FREE) {
			block = block->next;
			continue;
		}
		if (block->size < size || block->size >= best_size) {
			block = block->next;
			continue;
		}

		best_size = block->size;
		best_block = block;
		block = block->next;
	} while (block != mem_head);
	return best_block;
}
void preallocate_heap(void)
{
	struct block_meta *block = create_block(MMAP_THRESHOLD - SIZE_BLOCK_META, 0, MMAP_THRESHOLD);

	block->size = MMAP_THRESHOLD - SIZE_BLOCK_META;
	insert_list_right_of(block, get_last_list_block());
	block->status = STATUS_FREE;
	preallocated = 1;
}
struct block_meta *expand_last_block(struct block_meta *block, size_t total_size)
{
	size_t to_alloc = total_size - block->size;

	block->size += to_alloc;
	block->status = STATUS_ALLOC;

	void *p = sbrk(to_alloc);

	DIE(p == ERR_RET, "sbrk failed");
	return block;
}
void *expand_block(struct block_meta *block, size_t requested_size)
{
	struct block_meta *last_heap_block = get_last_heap_block();

	if (last_heap_block == block)
		return get_pointer_from_block_meta(expand_last_block(last_heap_block, requested_size));

	size_t needed_size = requested_size - block->size;

	if (!block->next || block->next->status != STATUS_FREE)
		return NULL;
	if (block->next->size + SIZE_BLOCK_META < needed_size)
		return NULL;

	block->size = requested_size;
	size_t remaining_size = block->next->size - needed_size;

	if (needed_size > block->next->size || remaining_size < 8 + SIZE_BLOCK_META) {
		remove_from_list(block->next);
		block->size = block->size + remaining_size + SIZE_BLOCK_META;
		return get_pointer_from_block_meta(block);
	}

	remove_from_list(block->next);
	remodel_block(block, requested_size, remaining_size);
	return get_pointer_from_block_meta(block);
}

void *alloc(size_t size, size_t check_size, size_t threshold)
{
	if (size == 0)
		return NULL;

	if (check_size < threshold && !preallocated)
		preallocate_heap();

	struct block_meta *best_block = find_best_block(size);

	if (best_block && check_size < threshold)
		return get_pointer_from_block_meta(split_block(best_block, size));

	struct block_meta *last_heap_block = get_last_heap_block();

	if (last_heap_block && last_heap_block->status == STATUS_FREE && check_size < threshold)
		return get_pointer_from_block_meta(expand_last_block(last_heap_block, size));

	struct block_meta *new_block = create_block(size, check_size, threshold);

	insert_list_right_of(new_block, get_last_list_block());
	return get_pointer_from_block_meta(new_block);
}

void *os_malloc(size_t size)
{
	size_t alligned_size = ALLIGN_SIZE(size);
	void *ptr = alloc(alligned_size, alligned_size, MMAP_THRESHOLD);
	return ptr;
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block = get_block_meta_from_pointer(ptr);

	if (block->status == STATUS_MAPPED) {
		remove_from_list(block);
		munmap(block, block->size + SIZE_BLOCK_META);
		return;
	}
	block->status = STATUS_FREE;
	coalesce_block(block);
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t total_size = ALLIGN_SIZE(size * nmemb);
	void *addr = alloc(total_size, total_size + SIZE_BLOCK_META, PAGE_SIZE);

	if (addr)
		memset(addr, 0, total_size);
	return addr;
}

void *os_realloc(void *ptr, size_t size)
{
	size_t alligned_size = ALLIGN_SIZE(size);

	if (!ptr)
		return os_malloc(alligned_size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block = get_block_meta_from_pointer(ptr);

	if (block->status == STATUS_FREE)
		return NULL;

	if (block->status == STATUS_MAPPED || alligned_size > MMAP_THRESHOLD) {
		void *new_ptr = os_malloc(alligned_size);

		memcpy(new_ptr, ptr, block->size > alligned_size ? alligned_size : block->size);
		os_free(ptr);
		return new_ptr;
	}

	if (block->size >= alligned_size)
		return get_pointer_from_block_meta(split_block(block, alligned_size));

	void *new_ptr = expand_block(block, alligned_size);

	if (new_ptr)
		return new_ptr;

	new_ptr = os_malloc(alligned_size);
	memcpy(new_ptr, ptr, block->size);
	os_free(ptr);
	return new_ptr;
}
