#include <elf.h>
#include <stdio.h>
#include <fcntl.h>

#include "common.h"
#include "elf64.h"

/// Let the test read itself for the test.
const char* file = "test_elf64";

int test_read_open_file()
{
  int fd = open(file, O_RDONLY|O_SYNC);
  TEST(fd > 0);
  LOG("SUCCCESS");
  return fd;
}

Elf64_Ehdr test_read_header(int fd)
{
  Elf64_Ehdr result;
  read_elf64_header(fd, &result);
  LOG("SUCCCESS");
  return result;
}

Elf64_Shdr* test_read_sections(int fd, Elf64_Ehdr eh)
{
  Elf64_Shdr* sections = NULL; 
  TEST(eh.e_shentsize == sizeof(Elf64_Shdr));
  TEST(read_elf64_sections(fd, eh, &sections) == eh.e_shnum); 
  TEST(sections != NULL);
  LOG("SUCCCESS");
  return sections;
}

Elf64_Phdr* test_read_segments(int fd, Elf64_Ehdr eh)
{
  Elf64_Phdr* segments = NULL;
  TEST(eh.e_phentsize == sizeof(Elf64_Phdr));
  TEST(read_elf64_segments(fd, eh, &segments) == eh.e_phnum);
  TEST(segments != NULL);
  LOG("SUCCESS");
  return segments;
}

Elf64_Sym* test_read_symbol(int fd, char* symbol, Elf64_Ehdr eh, Elf64_Shdr* sections)
{
  Elf64_Sym* sym = NULL;
  sym = find_symbol(fd, symbol, eh, sections);
  TEST(sym != NULL);
  LOG("SUCCESS %s [0x%08lx]", symbol, sym->st_value);
  return sym;
}

int main(void)
{
  LOG("TESTING elf64 library");
  int fd = test_read_open_file(); 
  Elf64_Ehdr eh = test_read_header(fd);
  Elf64_Shdr* sections = test_read_sections(fd, eh);
  print_elf64_sheaders(fd, eh,sections);
  Elf64_Phdr* segments = test_read_segments(fd, eh);
  char * symbols[] = {"test_read_open_file", "test_read_header", "test_read_sections"};
  for (int i = 0; i < 3; i++) {
    Elf64_Sym* sym = test_read_symbol(fd, symbols[i], eh, sections); 
    free(sym);
  }
  return 0;
}


