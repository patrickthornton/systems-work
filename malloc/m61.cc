#include "m61.hh"
#include <algorithm>
#include <cassert>
#include <cinttypes>
#include <climits>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <sys/mman.h>

#define FREED_SIZES_ITER std::map<uintptr_t, size_t>::iterator

/// MEMORY BUFFER DEFINITION (provided)

struct m61_memory_buffer {
  char *buffer;
  size_t pos = 0;
  size_t size = 8 << 20; /* 8 MiB */

  m61_memory_buffer();
  ~m61_memory_buffer();
};

static m61_memory_buffer default_buffer;

m61_memory_buffer::m61_memory_buffer() {
  void *buf = mmap(nullptr,    // Place the buffer at a random address
                   this->size, // Buffer should be 8 MiB big
                   PROT_WRITE, // We want to read and write the buffer
                   MAP_ANON | MAP_PRIVATE, -1, 0);
  // We want memory freshly allocated by the OS
  assert(buf != MAP_FAILED);
  this->buffer = (char *)buf;
}

m61_memory_buffer::~m61_memory_buffer() { munmap(this->buffer, this->size); }

/// METADATA DOCUMENTATION
///
/// active_metadata - a new type that keeps all relevant active region metadata
/// in one place; 				  this includes the size and the
/// file and line that asked for this region active_sizes - a map from pointers
/// (stored in uintptr_t variables) to active_metadata structs freed_sizes - a
/// map from pointers (stored in uintptr_t variables) to the respective region's
/// size
///
/// malloc_align - a global constant representing the greatest alignment of any
/// type on this machine; 			   malloc must return pointers
/// which align to this worst-case-scenario value
/// (we use align() to keep values aligned to malloc_align)
///
/// recent_frees - a deque containing the last max_recent_frees pointers to be
/// successfully freed via m61_free() max_recent_frees - the most elements that
/// recent_frees should ever contain at once before forgetting the least recent
/// num_recent_frees - the current number of frees in recent_frees
///
/// check_bytes - the number of bytes appended to every allocated region, which
/// should remain unedited; 			  if they change from their
/// original value of '7' (an arbitrary choice), we report a boundary write
/// error
///
/// gstats - global variable which tracks various statistics for
/// m61_statistics();
///
/// DATA INVARIANTS
/// 	1. each pointer in active_sizes must be aligned to malloc_align
/// 	2. each pointer in freed_sizes must be aligned to malloc_align
/// 	3. recent_frees must contain the max_recent_frees most recent freed
/// pointers
/// 	4. default_buffer.pos must be aligned to malloc_align

typedef struct {
  size_t sz;
  const char *file;
  int line;
} active_metadata;

static std::map<uintptr_t, active_metadata> active_sizes;
static std::map<uintptr_t, size_t> freed_sizes;

static const size_t malloc_align = alignof(std::max_align_t);

// raises 'sz' to nearest multiple of malloc_align
static size_t align(int sz) {
  return sz + (malloc_align - (sz % malloc_align));
}

static std::deque<void *> recent_frees;
static const size_t max_recent_frees = 32; // this may be adjusted
static size_t num_recent_frees = 0;

static const size_t check_bytes = 4; // this may be adjusted

static m61_statistics gstats = {
    .nactive = 0,
    .active_size = 0,
    .ntotal = 0,
    .total_size = 0,
    .nfail = 0,
    .fail_size = 0,
    .heap_min = ULONG_MAX, // maximum value possible for uintptr_t
    .heap_max = 0          // minimum value possible for uintptr_t
};

/// COALESCING FUNCTIONS (c.f. section 1)

static bool can_coalesce_up(FREED_SIZES_ITER it) {
  assert(it != freed_sizes.end());

  // Check if next sample exists
  auto next = it;
  ++next;
  if (next == freed_sizes.end())
    return false;

  return it->first + it->second == next->first;
}

static bool can_coalesce_down(FREED_SIZES_ITER it) {
  assert(it != freed_sizes.end());

  // Check if previous sample exists
  if (it == freed_sizes.begin())
    return false;

  auto prev = it;
  --prev;
  return prev->first + prev->second == it->first;
}

static void coalesce_up(FREED_SIZES_ITER it) {
  assert(can_coalesce_up(it));
  auto next = it;
  ++next;
  it->second += next->second;
  freed_sizes.erase(next);
}

/// HELPER FUNCTIONS TO ADD REGIONS TO MAPS;
/// these presume their arguments are data-invariant compliant (aligned, etc.)

static void add_freed_region(uintptr_t start, size_t sz) {
  freed_sizes.insert({start, sz});
  auto it = freed_sizes.find(start);
  while (can_coalesce_down(it))
    --it;
  while (can_coalesce_up(it))
    coalesce_up(it);

  // if current position at rightmost end of freed region, move position to left
  // end of new free space
  if (it->first + it->second ==
      (uintptr_t)&default_buffer.buffer[default_buffer.pos]) {
    default_buffer.pos -= it->second;
    assert(default_buffer.pos % malloc_align == 0); // INVARIANT 4
    freed_sizes.erase(it);
  }
}

static void add_active_region(uintptr_t start, size_t sz, const char *file,
                              int line) {
  active_sizes.insert({start, {sz, file, line}});

  // writing boundary-write error check bytes as per specs in METADATA
  // DOCUMENTATION
  size_t offset = start + sz - (uintptr_t)&default_buffer.buffer[0];
  for (size_t i = 0; i < check_bytes; ++i)
    default_buffer.buffer[i + offset] = 7;

  ++gstats.nactive;
  gstats.active_size += sz;
}

/// m61_malloc(sz, file, line)
///    Returns a pointer to `sz` bytes of freshly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    return either `nullptr` or a pointer to a unique allocation.
///    The allocation request was made at source code location `file`:`line`.

void *m61_malloc(size_t sz, const char *file, int line) {
  (void)file, (void)line; // avoid uninitialized variable warnings

  bool success = false;
  void *ptr;

  // try current position first; the && in the condition prevents potential
  // underflow
  if (default_buffer.pos + check_bytes < default_buffer.size &&
      default_buffer.size - default_buffer.pos - check_bytes >= sz) {
    ptr = &default_buffer.buffer[default_buffer.pos];
    assert((uintptr_t)ptr % malloc_align == 0); // INVARIANT 1
    default_buffer.pos += align(sz + check_bytes);
    assert(default_buffer.pos % malloc_align == 0); // INVARIANT 4
    add_active_region((uintptr_t)ptr, sz, file, line);
    success = true;
  }
  // otherwise, try to reuse a freed allocation
  else
    for (auto it = freed_sizes.begin(); it != freed_sizes.end(); ++it)
      if (check_bytes < it->second && it->second - check_bytes >= sz) {
        ptr = (void *)it->first;
        assert((uintptr_t)ptr % malloc_align == 0); // INVARIANTS 2 and 1

        // if the free region won't be used entirely, insert what's left over
        // into the map
        if (align(sz + check_bytes) < it->second)
          add_freed_region((uintptr_t)ptr + align(sz), it->second - align(sz));

        freed_sizes.erase(it);
        add_active_region((uintptr_t)ptr, sz, file, line);
        success = true;
        break;
      }

  if (success) {
    // log statistics
    ++gstats.ntotal;
    gstats.total_size += sz;

    uintptr_t ptr_val = (uintptr_t)ptr;
    if (ptr_val < gstats.heap_min)
      gstats.heap_min = ptr_val;
    if (ptr_val + sz - 1 > gstats.heap_max)
      gstats.heap_max = ptr_val + sz - 1;

    return ptr;
  }

  // otherwise, not enough space left in default buffer for allocation
  ++gstats.nfail;
  gstats.fail_size += sz;
  return nullptr;
}

/// m61_free(ptr, file, line)
///    Frees the memory allocation pointed to by `ptr`. If `ptr == nullptr`,
///    does nothing. Otherwise, `ptr` must point to a currently active
///    allocation returned by `m61_malloc`. The free was called at location
///    `file`:`line`.

void m61_free(void *ptr, const char *file, int line) {
  // avoid uninitialized variable warnings
  (void)ptr, (void)file, (void)line;

  // ERROR HANDLING
  // if ptr == nullptr, then nothing to be done
  if (!ptr)
    return;
  auto it = active_sizes.find((uintptr_t)ptr);
  if (it == active_sizes.end()) {
    if (std::find(recent_frees.begin(), recent_frees.end(), ptr) ==
        recent_frees.end()) {
      // if ptr points to address inside our buffer, 'not allocated'; otherwise,
      // 'not in heap'
      if (&default_buffer.buffer[0] <= ptr &&
          ptr <= &default_buffer.buffer[default_buffer.size - 1]) {
        fprintf(
            stderr,
            "MEMORY BUG: %s:%i: invalid free of pointer %p, not allocated\n",
            file, line, ptr);
        auto it_containing = active_sizes.upper_bound((uintptr_t)ptr);
        if (it_containing != active_sizes.end()) {
          --it_containing;
          fprintf(
              stderr,
              "%s:%i: %p is %lu bytes inside a %lu byte region allocated here",
              it_containing->second.file, it_containing->second.line, ptr,
              (uintptr_t)ptr - it_containing->first, it_containing->second.sz);
        }
      } else
        fprintf(stderr,
                "MEMORY BUG: %s:%i: invalid free of pointer %p, not in heap\n",
                file, line, ptr);
    } else
      fprintf(stderr,
              "MEMORY BUG: %s:%i: invalid free of pointer %p, double free\n",
              file, line, ptr);
    abort();
  }

  // boundary-write error checker
  size_t offset = it->first + (uintptr_t)it->second.sz -
                  (uintptr_t)&default_buffer.buffer[0];
  for (size_t i = 0; i < check_bytes; ++i)
    if (default_buffer.buffer[i + offset] != 7) {
      fprintf(
          stderr,
          "MEMORY BUG: %s:%i: detected wild write during free of pointer %p\n",
          file, line, ptr);
      abort();
    }

  --gstats.nactive;
  gstats.active_size -= it->second.sz;
  assert(it->first % malloc_align == 0); // INVARIANT 4
  add_freed_region(it->first, align(it->second.sz));
  active_sizes.erase(it);

  // INVARIANT 3
  if (num_recent_frees == max_recent_frees) {
    recent_frees.pop_front();
    --num_recent_frees;
  }
  recent_frees.push_back(ptr);
  ++num_recent_frees;
}

/// m61_calloc(count, sz, file, line)
///    Returns a pointer a fresh dynamic memory allocation big enough to
///    hold an array of `count` elements of `sz` bytes each. Returned
///    memory is initialized to zero. The allocation request was at
///    location `file`:`line`. Returns `nullptr` if out of memory; may
///    also return `nullptr` if `count == 0` or `size == 0`.

void *m61_calloc(size_t count, size_t sz, const char *file, int line) {
  if (!count || !sz || count > default_buffer.size ||
      sz > default_buffer.size) {
    ++gstats.nfail;
    gstats.fail_size += count * sz;
    return nullptr;
  }
  void *ptr = m61_malloc(count * sz, file, line);
  if (ptr)
    memset(ptr, 0, count * sz);
  return ptr;
}

/// m61_get_statistics()
///    Return the current memory statistics.

m61_statistics m61_get_statistics() { return gstats; }

/// m61_print_statistics()
///    Prints the current memory statistics.

void m61_print_statistics() {
  m61_statistics stats = m61_get_statistics();
  printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
         stats.nactive, stats.ntotal, stats.nfail);
  printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
         stats.active_size, stats.total_size, stats.fail_size);
}

/// m61_print_leak_report()
///    Prints a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_print_leak_report() {
  for (auto it = active_sizes.begin(); it != active_sizes.end(); ++it)
    fprintf(stdout, "LEAK CHECK: %s:%i: allocated object %p with size %lu\n",
            it->second.file, it->second.line, (void *)it->first, it->second.sz);
}
