#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sched.h>

#include "elf64.h"
#include "tyche_capabilities_types.h"
#if defined(CONFIG_X86) || defined(__x86_64__)
#include "x86_64_pt.h"
#elif defined(CONFIG_RISCV) || defined(__riscv)
#include "riscv48_pt.h"
#endif
#include "common.h"
#include "common_log.h"
#include "sdk_tyche_rt.h"
#include "sdk_tyche.h"
#include "backend.h"
#include "tyche_api.h"

#include "blake3.h"

//#define TYCHE_DEBUG 1

// ———————————————————————————— Local Functions ————————————————————————————— //
// Hash the region
static uint32_t PF_H = 1 << 3;
// Cleanup the region
static uint32_t PF_C = 1 << 4;
// Vital region
static uint32_t PF_V = 1 << 5;
/// Translate ELF flags into tyche memory access rights.
static memory_access_right_t translate_flags_to_tyche(Elf64_Word flags) {
  memory_access_right_t rights = 0;
  if ((flags & PF_R) == PF_R) {
    rights |= MEM_READ;
  }
  if ((flags & PF_X) == PF_X) {
    rights |= MEM_EXEC;
  }
  if ((flags & PF_W) == PF_W) {
    rights |= MEM_WRITE;
  }
  if((flags & PF_H) == PF_H) {
    rights |= MEM_HASH;
  }
  if ((flags & PF_C) == PF_C) {
    rights |= MEM_CLEANUP;
  }
  if ((flags & PF_V) == PF_V) {
    rights |= MEM_VITAL;
  }
  //TODO do user?
  rights |= MEM_SUPER;
  return rights;
}

/// Determines whether a segment type is confidential.
static int is_confidential(tyche_phdr_t tpe)
{
  switch (tpe) {
    case USER_STACK_CONF:
    case KERNEL_STACK_CONF:
    case PAGE_TABLES_CONF:
    case USER_CONFIDENTIAL:
    case KERNEL_CONFIDENTIAL:
      return 1;
      break;
    default: 
      return 0;
      break;
  }
  return 0;
}

/// Determines whether a segment type is loadable.
static int is_loadable(tyche_phdr_t tpe)
{
    if (tpe < USER_STACK_SB || tpe > KERNEL_PIPE) {
      return 0;
    }
    return 1;
}

static addr_t align_up(addr_t addr)
{
  if (addr % PT_PAGE_SIZE == 0) {
    return addr;
  }
  return (addr + PT_PAGE_SIZE) & ~(PT_PAGE_SIZE-1); 
}

static addr_t align_down(addr_t addr)
{
  if (addr % PT_PAGE_SIZE == 0) {
    return addr;
  }
  return (addr / PT_PAGE_SIZE) * PT_PAGE_SIZE;
}

static addr_t compute_real_size(addr_t start, addr_t size) {
  return (align_up(start + size) - align_down(start));
}

/// Look for the domain binary inside the current program's binary.
/// If destf is not null, it writes the extracted binary to the specified file.
static int extract_binary(elf_parser_t* parser, const char* self, const char* destf)
{
  void* dest = NULL;
  Elf64_Ehdr header;
  Elf64_Shdr* sections = NULL;
  Elf64_Shdr* domain_elf = NULL; 
  if (parser == NULL || self == NULL) {
    ERROR("Null argument: parser(%p), self(%p)", parser, self);
    goto failure;
  }
  memset(parser, 0, sizeof(elf_parser_t));

  parser->fd = open(self, O_RDONLY); 
  parser->type = FILE_ELF;
  if (parser->fd < 0) {
    ERROR("Failed to read self(%s)", self);
    goto failure;
  }
  // Read the header.
  read_elf64_header(parser, &header);
  
  // Read the sections.
  read_elf64_sections(parser, header, &sections);

  // Find the section for the domain.
  domain_elf = &sections[header.e_shnum-1];
  if (domain_elf->sh_type != SHT_NOTE) {
    ERROR("Wrong section type for domain");
    goto failure_free_sec;
  } 
  if (domain_elf == NULL) {
    ERROR("Unable to find the domain ELF section.");
    goto failure_free_sec;
  }
  
  // Now load the section.
  dest = read_section64(parser, *domain_elf); 
  if (dest == NULL) {
    ERROR("Unable to mmap memory for the domain ELF");
    goto failure_free_sec;
  }

  // If destf specified, dump it into the destination file.
  if (destf != NULL) {
    FILE* dest_file = fopen(destf, "wb");
    if (dest_file != NULL) {
      size_t written = fwrite(dest, 1, domain_elf->sh_size, dest_file);
      if (written != domain_elf->sh_size) {
        ERROR("Failed to write all the domain ELF bytes");
        fclose(dest_file);
        goto failure_free;
      } 
      fclose(dest_file);
    } else {
      ERROR("Failed to open destf(%s)", destf);
      goto failure_free;
    }
  }

  // Update the parser with the domain.
  close(parser->fd);
  parser->type = MEM_ELF;
  parser->memory.start = (char*) dest;
  parser->memory.offset = 0;
  parser->memory.size = domain_elf->sh_size;

  // Cleanup.
  free(sections);
  return SUCCESS;
failure_free:
  free(dest);
failure_free_sec:
  free(sections);
failure:
  return FAILURE;
}

static int domain_add_mslot(tyche_domain_t *domain, int is_pipe, usize size)
{
  domain_mslot_t *slot = NULL;
  if (domain == NULL) {
    ERROR("Null domain.");
    goto failure;
  }
  if (size > MAX_SLOT_SIZE) {
    ERROR("Slot size too big");
    goto failure;
  }
  if (size == 0) {
    ERROR("Attempt to add a null size slot");
    goto failure;
  }
  slot = malloc(sizeof(domain_mslot_t));
  if (slot == NULL) {
    ERROR("Failed to allocate a slot.");
    goto failure;
  }
  memset(slot, 0, sizeof(domain_mslot_t));
  dll_init_elem(slot, list);
  slot->id = (is_pipe)? domain->pipe_id++ : domain->mslot_id++;
  slot->size = size;
  // Add the slot to the domain.
  if (is_pipe) {
    dll_add(&(domain->pipes), slot, list);
  } else {
    dll_add(&(domain->mmaps), slot, list);
  }
  return SUCCESS;
failure:
  return FAILURE;
}

// Given a page number (pn), find the physical offset inside the domain's segment.
// Puts the result inside `result` and returns SUCCESS
// This should work as pn is basically the page address if everything was
// initialized from address 0. We go through segments looking for the one that
// contains the (pn >> PAGE_SIZE)th page over all allocations.
static int find_phys_address(tyche_domain_t *domain, usize pn, usize *result, int is_pipe, int is_page_table_root) {
  domain_mslot_t *slot = NULL;
  usize accumulated_size = 0;
  if (domain == NULL || result == NULL) {
    ERROR("Null argument");
    goto failure;
  }
  if (is_pipe) {
    dll_foreach(&(domain->pipes), slot, list) {
      if (pn >= accumulated_size && pn < (accumulated_size + slot->size)) {
        // offset within that slot.
        usize offset = pn - accumulated_size;
#if defined(CONFIG_X86) || defined(__x86_64__)
        *result = slot->physoffset + offset;
#elif defined(CONFIG_RISCV) || defined(__riscv)
        if (is_page_table_root) {
            *result = slot->physoffset + offset;
            //ERROR("Fixed PT Root: %lx", *result);
        } else {
            *result = ((slot->physoffset >> PT_PAGE_WIDTH) + (offset >> PT_FLAGS_RESERVED)) << PT_FLAGS_RESERVED;
            //ERROR("Fixed Normal Page: %lx", *result);
        }
#endif
        return SUCCESS;
      }
      accumulated_size += slot->size;
    }
  } else {
    dll_foreach(&(domain->mmaps), slot, list) {
      if (pn >= accumulated_size && pn < (accumulated_size + slot->size)) {
        // offset within that slot.
        usize offset = pn - accumulated_size;
#if defined(CONFIG_X86) || defined(__x86_64__)
        *result = slot->physoffset + offset;
#elif defined(CONFIG_RISCV) || defined(__riscv)
        if (is_page_table_root) {
            *result = slot->physoffset + offset;
            //ERROR("Fixed PT Root: %lx", *result);
        } else {
            *result = ((slot->physoffset >> PT_PAGE_WIDTH) + (offset >> PT_FLAGS_RESERVED)) << PT_FLAGS_RESERVED;
            //ERROR("Fixed Normal Page: %lx", *result); 
        }
#endif 
        return SUCCESS;
      }
      accumulated_size += slot->size;
    }
  }
failure:
  return FAILURE;
}

// —————————————————————————— Prototype functions ——————————————————————————— //

/// Calls both parse and load domain pointed by the file.
int init_domain_with_cores_traps(
    tyche_domain_t* domain,
    usize cores,
    usize traps,
    usize perms);

/// Parses an ELF binary created by tychools.
/// All the segments for the domain should have OS-specific types.
/// The page tables must be present, as well as the stacks and shared regions.
int parse_domain(tyche_domain_t* domain);

/// Loads an domain created with tychools.
/// It patches the page tables that should be located inside one of the segments.
int load_domain(tyche_domain_t* domain);

// ——————————————————————————————— Functions ———————————————————————————————— //

int init_domain_with_cores_traps(
    tyche_domain_t* domain,
    usize cores,
    usize traps,
    usize perms)
{
  if (domain == NULL || domain->parser.elf.memory.start == NULL) {
    ERROR("Null argument provided: domain(%p)", domain);
    goto failure;
  }
  domain->traps = traps;
  domain->core_map = cores;
  domain->perms = perms;
  if (parse_domain(domain) != SUCCESS) {
    ERROR("Unable to parse the domain");
    goto failure;
  }
  if (load_domain(domain) != SUCCESS) {
    ERROR("Unable to load the domain");
    goto failure;
  }
  // All done!
  return SUCCESS;
failure:
  return FAILURE;
}

int parse_domain(tyche_domain_t* domain)
{
  size_t segments_size = 0;
  size_t pipes_size = 0;

  // Common checks.
  if (domain == NULL) {
    ERROR("domain structure is null."); 
    goto failure;
  }
  if (domain->parser.elf.memory.start == NULL) {
    ERROR("The domain's memory content is null.");
    goto failure;
  }
  if (domain->mslot_id != 0) {
    ERROR("The domain already has mslots!");
    goto failure;
  }
  dll_init_list(&(domain->shared_regions));
  dll_init_list(&(domain->mmaps));
  dll_init_list(&(domain->pipes));
  
  // Parse the ELF.
  read_elf64_header(&domain->parser.elf, &(domain->parser.header));
  read_elf64_segments(&domain->parser.elf,
      domain->parser.header, &(domain->parser.segments)); 
  //@note: We do not need to parse the sections as tychools works on segments. 

  // Set up the entry point.
  domain->config.entry = domain->parser.header.e_entry;

  // Find the stack and the shared regions.
  for (int i = 0; i < domain->parser.header.e_phnum; i++) {
    Elf64_Phdr* segment = &domain->parser.segments[i];
    // Found the user stack.
    if (segment->p_type == USER_STACK_SB || segment->p_type == USER_STACK_CONF) {
      domain->config.user_stack = segment->p_vaddr + segment->p_memsz - STACK_OFFSET_TOP; 
    }
    // Found the kernel stack.
    if (segment->p_type == KERNEL_STACK_SB || segment->p_type == KERNEL_STACK_CONF) {
      domain->config.stack = segment->p_vaddr + segment->p_memsz - STACK_OFFSET_TOP;
    }
    // Found a shared segment.
    if (segment->p_type == KERNEL_SHARED || segment->p_type == USER_SHARED) {
      domain_shared_memory_t *shared = malloc(sizeof(domain_shared_memory_t));
      if (shared == NULL) {
        ERROR("Unable to malloc domain_shared_memory_t");
        goto failure;
      } 
      memset(shared, 0, sizeof(domain_shared_memory_t));
      shared->segment = segment;
      dll_init_elem(shared, list);
      dll_add(&(domain->shared_regions), shared, list);
    }
    // Found the page tables.
    if (segment->p_type == PAGE_TABLES_SB || segment->p_type == PAGE_TABLES_CONF) {
      domain->config.page_table_root = segment->p_vaddr;
      //TODO figure out if we want to keep a pointer to the segment.
    }
  }

  //////////////////////////////////////////////////////////
  // Calculate expected attestation hash of given domain. //
  //////////////////////////////////////////////////////////

  // Sort ELF segments by vaddr using a simple selection sort algorithm
  int n_loadable = domain->parser.header.e_phnum;
  int * sorted_idxs = malloc(sizeof(int)*n_loadable);

  for (int i = 0; i < n_loadable; i++) {
      sorted_idxs[i] = i;
  }

  for (int i = 0; i < n_loadable - 1; i++) {
      for (int j = i + 1; j < n_loadable; j++) {
          if (domain->parser.segments[sorted_idxs[i]].p_vaddr > domain->parser.segments[sorted_idxs[j]].p_vaddr) {
              int temp = sorted_idxs[i];
              sorted_idxs[i] = sorted_idxs[j];
              sorted_idxs[j] = temp;
          }
      }
  }

  // Initialize blake3 hasher
  #define BLOCK_SIZE 16*1024
  #define HASH_LEN 32
  uint8_t zeroes[BLOCK_SIZE] = {0}; // convenience for hashing segments where filesz < memsz
  uint8_t buf[BLOCK_SIZE] = {0};
  uint8_t hash[HASH_LEN] = {0};

  blake3_hasher hasher;
  blake3_hasher_init(&hasher);

  // Iterate over segments, hashing contents appropriately
  for (int i = 0; i < n_loadable; i++) {
    int idx = sorted_idxs[i];
    Elf64_Phdr seg = domain->parser.segments[idx];

    if (!is_loadable(seg.p_type)) {
      continue;
    }

    // This segment is modified anyway, correctness is proved by Tyche's method of producing the measurement.
    if (seg.p_type == PAGE_TABLES_CONF) {
      continue;
    }

    // format of the hash per page is:
    //   v_addr: 8 bytes
    //   size:   8 bytes
    //   flags:  8 bytes
    //   status: 1 byte
    //   [data]: size bytes
    //
    //   flags is the copy of the flags from the PTE
    //   status is 0 for shared, 1 for unique and zeroed, 2 for unique & hashed
    //   [data] only follows if status==2.

    // The real size of allocated memory for the segment (size) may be larger than the
    // stored bytes in the ELF (filesz). So we hash `filesz` bytes from the ELF,
    // and then `size-filesz` bytes of zeroes.
    size_t size = compute_real_size(seg.p_vaddr, seg.p_memsz);
    elf_parser_t * parser = &domain->parser.elf;
  
    if (parser->type == FILE_ELF) {
      lseek(parser->fd, seg.p_offset, SEEK_SET);
    } else {
      parser->memory.offset = seg.p_offset;
    }

    // Determine status byte
    uint8_t status = 0;
    if (seg.p_type != USER_SHARED && seg.p_type != KERNEL_SHARED) {
      status = should_zero(seg) ? 1 : 2;
    }

    // Create bitfield matching the PTE flag bits.
    // All PTEs for a given segment should have the same PTE flags.
    uint64_t flags = 0;
    if (seg.p_flags & PF_R)
      flags |= 1 << 0;

    if (seg.p_flags & PF_W)
      flags |= 1 << 1;

    if ((seg.p_flags & PF_X) != PF_X)
      flags |= ((uint64_t)1 << 63);

    uint64_t pt_size = PT_PAGE_SIZE;
    size_t current_read = 0;

    uint64_t p_vaddr = seg.p_vaddr & PT_PHYS_PAGE_MASK;
    size_t unaligned = seg.p_vaddr % PT_PAGE_SIZE;
    for (int i = 0; i < size / PT_PAGE_SIZE; i++) {
      uint64_t vaddr = p_vaddr + i * PT_PAGE_SIZE;

      blake3_hasher_update(&hasher, &vaddr, sizeof(uint64_t));
      blake3_hasher_update(&hasher, &pt_size, sizeof(uint64_t));
      blake3_hasher_update(&hasher, &flags, sizeof(uint64_t));
      blake3_hasher_update(&hasher, &status, sizeof(uint8_t));

      // If unique & we should hash contents.
      if (status == 2) {
        size_t mem_to_read, zeroes_to_read;

        // If we have an unaligned segment,
        if (vaddr < seg.p_vaddr) {
          // we need to hash some zeroes first.
          blake3_hasher_update(&hasher, zeroes, unaligned);
          // If the remaining memory doesn't fill out the page,
          // we still have some zeroes to read after the segment data.
          if (seg.p_filesz + unaligned < PT_PAGE_SIZE) {
            mem_to_read  = seg.p_filesz;
            zeroes_to_read = PT_PAGE_SIZE - seg.p_filesz - unaligned;
          } else  {
            mem_to_read = PT_PAGE_SIZE - unaligned;
            zeroes_to_read = 0;
          }
        } else {
          // Determine how many bytes from ELF to read for this page. ELFs do not
          // store memory to fill out are page, so we need to read from zeroes
          // at the end of a segment.
          if (current_read < seg.p_filesz + unaligned) {
            mem_to_read = seg.p_filesz + unaligned - current_read > PT_PAGE_SIZE ? PT_PAGE_SIZE : seg.p_filesz + unaligned - current_read;
            zeroes_to_read = mem_to_read < PT_PAGE_SIZE ? PT_PAGE_SIZE - mem_to_read : 0;
          } else {
            mem_to_read = 0;
            zeroes_to_read = PT_PAGE_SIZE;
          }
        }

        // Read from ELF
        if (mem_to_read > 0) {
          if (parser->type == FILE_ELF) {
            read(parser->fd, buf, mem_to_read);
            blake3_hasher_update(&hasher, buf, mem_to_read);
          } else {
            blake3_hasher_update(&hasher, parser->memory.start + parser->memory.offset, mem_to_read);
            parser->memory.offset += mem_to_read;
          }
        }

        // Read from zeroes
        if (zeroes_to_read > 0) {
          blake3_hasher_update(&hasher, zeroes, zeroes_to_read);
        }

        current_read += PT_PAGE_SIZE;
      }
    }
  }

  blake3_hasher_finalize(&hasher, hash, HASH_LEN);

  char logbuf[128] = {0};
  int n = sprintf(logbuf, "Final hash: 0x");
  for (int i = 0; i < HASH_LEN; i++) {
    sprintf(&logbuf[n + i*2], "%02x", hash[i]);
  }
  LOG(logbuf);

  ////////////////////////////////////////////////////////////////
  // END calculating expected attestation hash of given domain. //
  ////////////////////////////////////////////////////////////////

  // Compute the memory slots required for the segments.
  // Go through segments.
  for (int i = 0; i < domain->parser.header.e_phnum; i++) {
    Elf64_Word tpe = domain->parser.segments[i].p_type;
    usize total = 0;
    usize seg_size = 0;
    int is_pipe = 0;

  Elf64_Word	p_type;			/* Segment type */
  Elf64_Word	p_flags;		/* Segment flags */
  Elf64_Off	p_offset;		/* Segment file offset */
  Elf64_Addr	p_vaddr;		/* Segment virtual address */
  Elf64_Addr	p_paddr;		/* Segment physical address */
  Elf64_Xword	p_filesz;		/* Segment size in file */
  Elf64_Xword	p_memsz;		/* Segment size in memory */
  Elf64_Xword	p_align;		/* Segment alignment */



    LOG("seg loadable %d vaddr 0x%x memsz 0x%x type %x filesz 0x%x align %x, flags %x",
      is_loadable(tpe),
      domain->parser.segments[i].p_vaddr,
      domain->parser.segments[i].p_memsz,
      tpe,
      domain->parser.segments[i].p_filesz,
      domain->parser.segments[i].p_align,
      domain->parser.segments[i].p_flags
    );

    // Only consider loadable segments instrumented by tychools.
    if (!is_loadable(tpe)) {
      continue;
    }
    seg_size = compute_real_size(domain->parser.segments[i].p_vaddr,
        domain->parser.segments[i].p_memsz);
    if (seg_size % PT_PAGE_SIZE != 0) {
      ERROR("The segment size is %zu", segments_size);
      goto close_failure;
    }

    // Special case, we handle the pipes.
    is_pipe = tpe == KERNEL_PIPE;

    DEBUG("Segments size so far os %lx, Pipe size so far is %lx, This segment size is %llx, MAX_SLOT_SIZE is %x", segments_size, pipes_size, seg_size, MAX_SLOT_SIZE);
    size_t old_size = is_pipe ? pipes_size: segments_size;
    if (old_size >= MAX_SLOT_SIZE) { // Old size should be smaller than MAX_SLOT_SIZE.
      ERROR("Old size should be smaller than MAX_SLOT_SIZE.");
      goto close_failure; 
    }

    if (seg_size + old_size >= MAX_SLOT_SIZE){ // Can everything fit in one slot?
      DEBUG("Create a new slot");
      domain_add_mslot(domain, is_pipe, MAX_SLOT_SIZE);
      seg_size -= (MAX_SLOT_SIZE - old_size);
      if (is_pipe) {
        pipes_size = 0;
      } else {
        segments_size = 0;
      }

      // If the segment is still too big, cut it into MAX_SLOT_SIZE slots.
      while (seg_size >= MAX_SLOT_SIZE){
        DEBUG("Create a new slot for this segment");
        domain_add_mslot(domain, is_pipe, MAX_SLOT_SIZE);
        seg_size -= MAX_SLOT_SIZE;
      }
    }

    // Add the last segment.
    if (is_pipe) {
      pipes_size += seg_size;
      if (pipes_size >= MAX_SLOT_SIZE) {
        ERROR("Pipes size should be smaller thanMAX_SLOT_SIZE");
        goto close_failure;
      }
    } else {
      segments_size += seg_size;
      if (segments_size >= MAX_SLOT_SIZE) {
        ERROR("segments_size >= MAX_SLOT_SIZE");
        goto close_failure;
      }
    }
  }

  // Add the last segment.
  if (domain_add_mslot(domain, 0, segments_size) != SUCCESS) {
    ERROR("Last slot failure");
    goto close_failure;
  }
  // Add the last pipe.
  if (pipes_size != 0 && domain_add_mslot(domain, 1, pipes_size) != SUCCESS) {
    ERROR("Adding pipe error.");
    goto close_failure;
  }
  
  return SUCCESS;
close_failure:
  free(domain->parser.elf.memory.start);
  domain->parser.elf.memory.start = NULL;
failure:
  return FAILURE;
}

int should_hash(Elf64_Phdr seg) {
  Elf64_Word type = seg.p_type;
  Elf64_Word flags = seg.p_flags;

  if (type == USER_STACK_SB ||
      type == USER_STACK_CONF ||
      type == USER_SHARED ||
      type == KERNEL_STACK_SB ||
      type == KERNEL_STACK_CONF ||
      type == KERNEL_SHARED ||
      type == KERNEL_PIPE) {
      return 0;
  }

  // RWX confidential pages aren't normal. Easy way to flag regions added by manifest.
  // Really, we should have the tyche loader add the PF_H flag to segments in the manifest
  // instead of looking for particular combos here :-)
  if (type == USER_CONFIDENTIAL || type == KERNEL_CONFIDENTIAL) {
    if ((flags & PF_R) && (flags & PF_W) && (flags & PF_X)) {
      return 0;
    }
  }

  return 1;
}

int should_zero(Elf64_Phdr seg) {
  Elf64_Word type = seg.p_type;
  Elf64_Word flags = seg.p_flags;

  // RWX confidential pages aren't normal. Easy way to flag regions added by manifest.
  if (type == USER_CONFIDENTIAL || type == KERNEL_CONFIDENTIAL) {
    if ((flags & PF_R) && (flags & PF_W) && (flags & PF_X)) {
      return 1;
    }
  }

  if (type == USER_STACK_SB ||
      type == USER_STACK_CONF ||
      type == KERNEL_STACK_SB ||
      type == KERNEL_STACK_CONF) {
        return 1;
      }

  return 0;
}

int load_domain(tyche_domain_t* domain)
{
    //ERROR("Loading domain");
  usize size = 0;
  usize phys_size = 0;
  domain_mslot_t *slot = NULL;
  if (domain == NULL) {
    ERROR("The domain is null.");
    goto failure;
  }

  if (domain->parser.segments == NULL) {
    ERROR("The domain is not parsed. Call parse_domain first!");
    goto failure;
  }
  
  // Call the backend to create the domain.
  if (backend_td_create(domain) != SUCCESS) {
    ERROR("Backend error creating the backend.");
    goto failure;
  }

  // Call the backend to allocate the domain's memory.
  if (backend_td_alloc_mem(domain) != SUCCESS) {
    ERROR("Backend error allocating domain's memory.");
    goto failure;
  }

  // Patch the pipes if any.
  if (sdk_handle_pipes != NULL && sdk_handle_pipes(domain) != SUCCESS) {
    ERROR("Problem in callback to handle pipes");
    goto failure;
  }

  // Copy the domain's content.
  phys_size = 0;
  slot = domain->mmaps.head;
  DEBUG("Slot %lld is virtual offset %llx and physical offset %llx, size %llx", slot->id, slot->virtoffset, slot->physoffset, slot->size);
  for (int i = 0; i < domain->parser.header.e_phnum; i++) {
    Elf64_Phdr seg = domain->parser.segments[i];
    // The segment is not loadable.
    if (!is_loadable(seg.p_type) || seg.p_type == KERNEL_PIPE) {
      // TODO: Check if the segment should be initialized with 0s (e.g. .bss).
      continue;
    }
  
    // LOG("load_domain: parsing segment %i: ptype 0x%08x vaddr 0x%x len 0x%x flags 0x%04x", i, seg.p_type, seg.p_vaddr, seg.p_memsz, seg.p_flags);

    if (slot == NULL) {
      ERROR("Slot should not be null");
      goto failure;
    }
    addr_t size = compute_real_size(seg.p_vaddr, seg.p_memsz);
    DEBUG("Segment %d is p_vaddr %lx, p_memsz %lx, size %llx", i, seg.p_vaddr, seg.p_memsz, size);

    addr_t seg_offset = seg.p_vaddr - align_down(seg.p_vaddr);
    addr_t dest = slot->virtoffset + phys_size;
    addr_t load_dest = dest + seg_offset;
    memory_access_right_t flags = translate_flags_to_tyche(seg.p_flags);

    // Alter flags to include hash.
    int ret = should_hash(seg);
    // LOG("Segment %i: should_hash %i", i, ret);
    if (ret) {
      flags |= MEM_HASH;
    }

    load_elf64_segment(&domain->parser.elf, (void*) load_dest, seg);

    // If segment is shared, fix it in the shared_segments.
    // For now, do it in a non-efficient way.
    domain_shared_memory_t* shared =  NULL;
    dll_foreach(&(domain->shared_regions), shared, list) {
      if (shared->segment->p_vaddr == seg.p_vaddr) {
        // This should be page aligned too.
        if (dest != load_dest) {
          ERROR("A shared region is not page aligned.");
          goto failure;
        }
        shared->untrusted_vaddr = load_dest;
      }
    }

    //ERROR("About to fix PTs Loading domain");

    // Fix the page tables here.
    // We need to go through and compute the offset of addresses in segments.
    // We should have the guarantee that start and end fall within the same
    // memory slot by construction for the moment (provided we don't have 2^10
    // pages in the page tables).
    if (seg.p_type == PAGE_TABLES_CONF || seg.p_type == PAGE_TABLES_SB) {
        //ERROR("Loading domain - fixing segment PTs");
      // We hope the page tables are aligned, let's do a quick check.
      if (seg_offset != 0) {
        ERROR("Page tables are not page aligned");
        goto failure;
      }
      uint64_t* start = (uint64_t*) dest;
      uint64_t* end = (uint64_t*)(((uint64_t) dest) + size);
      //We should go through the segments and find the right address and fix it.
      for (; start < end; start++) {
        if (*start != 0) {
            uint64_t page = (*start & PT_PHYS_PAGE_MASK);
            int is_pipe = (*start & PT_PAGE_PIPE) == PT_PAGE_PIPE;
            usize fixed_addr = 0;
            //ERROR("About to find phys_addr for %lx", page);
            if (find_phys_address(domain, page, &fixed_addr, is_pipe, 0) != SUCCESS) {
              ERROR("Unable to find the physaddress for %lx", page);
              goto failure;
            }
            *start &= ~(PT_PHYS_PAGE_MASK);
            *start |= (uint64_t) fixed_addr;
            //ERROR("Address fixed to: %lx",*start);
            // Remove the pipe.
            if (is_pipe) {
              *start &= ~(PT_PAGE_PIPE);
            }
        }
      }
      // Fix the root page tables here.
      usize fixed_cr3 = 0;
      if (find_phys_address(domain, domain->config.page_table_root, &fixed_cr3, 0, 1) != SUCCESS) {
        ERROR("Unable to find the cr3 in the mslots");
        goto failure;
      }
      domain->config.page_table_root = fixed_cr3;
    }

    // Now map the segment.
    int conf_or_shared = is_confidential(seg.p_type)? CONFIDENTIAL : SHARED; 
    if (conf_or_shared == CONFIDENTIAL) {
      flags |= MEM_CONFIDENTIAL;
    }

    // Check we fit in this slot.
    if (seg.p_type != KERNEL_PIPE && phys_size + size > slot->size) { // Need to register the segment over several slots
      DEBUG("Overflow to next slot");
      //Register what you can
      addr_t new_size = slot->size - phys_size; // Register what you can in that slot
      size -= new_size;
      if (backend_td_register_region(
          domain,
          dest,
          new_size,
          flags,
          conf_or_shared) != SUCCESS) {
        ERROR("Unable to map segment for domain %d at %llx",
            domain->handle, dest);
        goto failure;
      }
      if (phys_size + new_size != slot->size) { // Confirm that the slot is full
        ERROR("phys_size + new_size != slot->size");
        goto failure;
      }
      DEBUG("Slot %lld is virtual offset %llx and physical offset %llx, size %llx is being fully registered", slot->id, slot->virtoffset, slot->physoffset, slot->size);
      DEBUG("Next Slot %lld is virtual offset %llx and physical offset %llx, size %llx", slot->list.next->id, slot->list.next->virtoffset, slot->list.next->physoffset, slot->list.next->size);
      slot = slot->list.next;
      dest = slot->virtoffset;

      while (size > slot->size) { // If the segement is still bigger than the next slot, register what you canm
        //Register slot->size
        addr_t new_size = slot->size;
        size -= new_size;
        if (backend_td_register_region(
          domain,
          dest,
          new_size,
          flags,
          conf_or_shared) != SUCCESS) {
            ERROR("Unable to map segment for domain %d at %llx", domain->handle, dest);
            goto failure;
        }
        DEBUG("Slot %lld is virtual offset %llx and physical offset %llx, size %llx is being fully registered", slot->id, slot->virtoffset, slot->physoffset, slot->size);
        DEBUG("Next Slot %lld is virtual offset %llx and physical offset %llx, size %llx", slot->list.next->id, slot->list.next->virtoffset, slot->list.next->physoffset, slot->list.next->size);
        slot = slot->list.next;
        dest = slot->virtoffset;
      }
      
      phys_size = 0; // We are starting a new slot
    }

    //Register the last part of the segment
    if (backend_td_register_region(
          domain,
          dest,
          size,
          flags,
          conf_or_shared) != SUCCESS) {
      ERROR("Unable to map segment for domain %d at %llx",
          domain->handle, dest);
      goto failure;
    }
    // Update the current size.
    phys_size+= size;
    if (phys_size > slot->size) {
      ERROR("We went above the slot size.");
      goto failure;
    }
    if (phys_size == slot->size) {
      phys_size = 0;
      slot = slot->list.next;
    }
  }
  DEBUG("Done mprotecting domain %d's sections", domain->handle);

  // Set the traps.
  if (backend_td_config(
        domain, TYCHE_CONFIG_TRAPS, domain->traps) != SUCCESS) {
    ERROR("Unable to set the traps for the domain %d", domain->handle);
    goto failure;
  }
  // Set the cores. 
  if (backend_td_config(
        domain, TYCHE_CONFIG_CORES, domain->core_map) != SUCCESS) {
    ERROR("Unable to set the cores for the domain %d", domain->handle);
    goto failure;
  }
  // Set the domain permissions.
  if (backend_td_config(
        domain, TYCHE_CONFIG_PERMISSIONS, domain->perms) != SUCCESS) {
    ERROR("Unable to set the permission on domain %d", domain->handle);
    goto failure;
  }

  // Do the default configuration for mgmt.
  for (unsigned int p = TYCHE_CONFIG_R16; p < TYCHE_NR_CONFIGS; p++) {
    if (backend_td_config(domain, p, ~((usize) 0)) != SUCCESS) {
      ERROR("Unable to set the permission %u", p);
      goto failure;
    }
  }
  // For the moment support maximum 32 cores, 
  for (usize i = 0; i < MAX_CORES; i++) {
    // Create the core context.
    if ((domain->core_map & (1ULL << i)) == 0) {
      continue;
    }
    if (backend_td_create_vcpu(domain, i) != SUCCESS) {
      ERROR("Unable to create vcpu on core %lld | core_map: 0x%llx", i, domain->core_map); 
      goto failure;
    }
    if (backend_td_init_vcpu(domain, i) != SUCCESS) {
      ERROR("Unable to init the vcpu on core %lld", i);
      goto failure;
    }
  }

  // Commit the domain.
  if (backend_td_commit(domain)!= SUCCESS) {
    ERROR("Unable to commit the domain %d", domain->handle);
    goto failure;
  }
  DEBUG("Done loading domain %d", domain->handle);
  return SUCCESS;
failure:
  return FAILURE;
}

// ————————————————————————————— API Functions —————————————————————————————— //
int sdk_create_domain(
    tyche_domain_t* dom,
    const char* self,
    usize cores,
    usize traps,
    usize perms)
{
  // LOG("Called SDK create domain");

  char* dump =  NULL;
  if (dom == NULL) {
    ERROR("Provided domain structure is null.");
    goto failure;
  }
  if (self == NULL) {
    ERROR("No name for the program provided.");
    goto failure;
  }
 
  // If the value is set, we will dump the extracted binary.
  dump = getenv(DUMP_BIN);
  memset(dom, 0, sizeof(tyche_domain_t));

  // We need to extract the domain from the current binary.
  if (extract_binary(&(dom->parser.elf), self, dump) != SUCCESS) {
    ERROR("Error extracting the domain ELF from the current binary.");
    goto failure;
  } 

  // The binary is already instrumented, let's load it.
  if (init_domain_with_cores_traps(dom, cores, traps, perms) != SUCCESS) {
    ERROR("Unable to load tychools binary");
    goto failure;
  } 
  return SUCCESS;
failure:
  return FAILURE;
}

int sdk_call_domain_on_core(tyche_domain_t* domain, usize core, uint32_t delta)
{
  int cpu_id = sched_getcpu();
  if (domain == NULL) {
    ERROR("The provided domain is null.");
    goto failure;
  } 

  // This is just a sanity check but the thread might get migrated between
  // time of check and until it reaches the vmcall
  if (core != cpu_id) {
    ERROR("CPU %d cannot run vcpu on core %lld", cpu_id, core);
    goto failure;
  }

  if (backend_td_vcpu_run(domain, core, delta) != SUCCESS) {
    DEBUG("Unable to switch to the domain %d on core %lld", domain->handle, core);
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int sdk_call_domain(tyche_domain_t* domain)
{
  return sdk_call_domain_on_core(domain, sched_getcpu(), 0);
}

int sdk_call_domain_for(tyche_domain_t* domain, uint32_t delta)
{
  return sdk_call_domain_on_core(domain, sched_getcpu(), delta);
}

int sdk_delete_domain(tyche_domain_t* domain)
{
  if (domain == NULL) {
    ERROR("The provided domain is null.");
    goto failure;
  }
  // First call the driver.
  if (backend_td_delete(domain) != SUCCESS) {
    ERROR("Unable to delete the domain %d", domain->handle);
    goto failure;
  }
  // Now collect everything else.
  // The config.
  while (!dll_is_empty(&(domain->shared_regions))) {
    domain_shared_memory_t* sec = domain->shared_regions.head;
    dll_remove(&(domain->shared_regions), sec, list);
    free(sec);
  }
  free(domain->parser.segments);
  free(domain->parser.sections);
  free(domain->parser.strings);
  free(domain->parser.elf.memory.start);
  return SUCCESS;
failure:
  return FAILURE;
}

// ———————————————————————— Pipes related functions ————————————————————————— //

int sdk_create_pipe(tyche_domain_t *domain, usize *id, usize physoffset,
    usize size, memory_access_right_t flags, usize width) {
  if (domain == NULL || id == NULL || width == 0) {
    ERROR("the id is null or width is 0");
    goto failure;
  }
  return backend_create_pipe(domain, id, physoffset, size, flags, width);
failure:
  return FAILURE;
}

int sdk_acquire_pipe(tyche_domain_t *domain, domain_mslot_t *slot) {
  if (domain == NULL || slot == NULL) {
    ERROR("The domain is null.");
    goto failure;
  }
  return backend_acquire_pipe(domain, slot);
failure:
  return FAILURE;
}
