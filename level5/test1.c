#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int alloc_size;
static char* memory;

void segv_handler (int signal_number)
{
  printf ("memory accessed!\n");
    mprotect (memory, alloc_size, PROT_READ | PROT_WRITE);
}

int main ()
{
	 int fd;
	 struct sigaction sa;

		  /* 初始化segv_handler为SIGSEGV的句柄。*/
		    memset (&sa, 0, sizeof (sa));
			  sa.sa_handler = &segv_handler;
			    sigaction (SIGSEGV, &sa, NULL);

				  /* 使用映射/dev/zero分配内存页。最初映射的内存为只写。*/
				    alloc_size = getpagesize ();
					  fd = open ("./list1", O_RDONLY);
					    memory = mmap (NULL, alloc_size, PROT_WRITE, MAP_PRIVATE, fd, 0);
						  close (fd);
						    /* 写页来获得一个私有复制。 */
							  memory[0] = 0;
							    /* 使内存为不可写。 */
								  mprotect (memory, alloc_size, PROT_NONE);
								    /* 写分配内存区域。 */
									  memory[0] = 1;
									   /* 所有工作都结束；unmap内存映射。 */
										  printf ("all done");
										    munmap (memory, alloc_size);

return 0;
}
