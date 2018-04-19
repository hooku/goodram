#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <stdio.h>
#include <tchar.h>

#include <Windows.h>

#define APP_VER                     1
#define QUICK_TEST                  1
#define KILO                        1024

#define MAX_ALLOC_MEMORY            8*256*1024*1024     // 2 GB
#define PERSEVERED_MEMORY           64*1024*1024        // 64 MB    how much memory will be preserved

#define REQUESTED_MEMORY            256*1024*1024       // 256 MB
#define MAX_DEFECT_RAM_COUNT        16                  // how much defective memory info app can hold

#define TEST_PATTERN                0xFFFFFFFF


BOOL acquire_lockpage_privilege (HANDLE );
BOOL detect_defect_ram          (void *);

int page_size;
unsigned int memory_to_request = REQUESTED_MEMORY;

#ifdef QUICK_TEST
    unsigned int test_pattern[] = { 0xFFFFFFFF };
#else
    unsigned int test_pattern[] = { 0x0, 0x55555555, 0xAAAAAAAA, 0xFFFFFFFF, 0x44444444, 0xFFFFFFFF };
#endif

unsigned char *defect_ram_list[MAX_DEFECT_RAM_COUNT];
int defect_ram_count = 0;

void add_defect_ram(unsigned char *addr)
{
    int i_defect_ram;
    unsigned char *page_addr;

    // t = (((unsigned int)addr) % page_size);

    page_addr = ((unsigned char *)addr - (((unsigned int)addr) % page_size));
    for (i_defect_ram = 0; i_defect_ram < defect_ram_count; i_defect_ram ++)
    {
        if (defect_ram_list[i_defect_ram] == page_addr)
        {
            return ;
        }
    }

    defect_ram_list[defect_ram_count] = page_addr;
    defect_ram_count ++;

    _tprintf(_T("Bad Mem Addr=0x%02x\n"), page_addr);
}

int detect_defect_ram(void *base_addr, int num_of_pages)
{
    int i_pattern;
    int pattern_count = sizeof(test_pattern)/sizeof(unsigned int);

    int i_page, page_len;
    int bad_word_count = 0;

    unsigned int    *current_page_base_addr,
                    *current_page_addr;

    page_len = page_size/sizeof(unsigned int);

    // test memory with various pattern
    for (i_pattern = 0; i_pattern < pattern_count; i_pattern ++)
    {
        current_page_base_addr = (unsigned int *)base_addr;

        _tprintf(_T("Test with pattern %d...\n"), i_pattern);

        // fill memory with pattern:
        memset(current_page_base_addr, test_pattern[i_pattern], memory_to_request);

        for (i_page = 0; i_page < num_of_pages; i_page ++)
        {
            //memset(current_page_base_addr, FILL_PATTERN, page_size);

            // validate each page correctness:
            for (current_page_addr = current_page_base_addr; 
                current_page_addr < (current_page_base_addr + page_len); current_page_addr ++)
            {
                if ((*current_page_addr) != test_pattern[i_pattern])
                {
                    bad_word_count ++;
                    add_defect_ram((unsigned char *)current_page_addr);
                }
            }
            current_page_base_addr += page_len;
        }
    }

    _tprintf(_T("Test Done\n"), i_pattern);

    if (bad_word_count > 0)
    {
        return FALSE;
    }
    return TRUE;
}

void test_defect_ram()
{
    float failure_times, test_times, success_times;
    int i_defect_ram;
    unsigned int *current_page_addr;

    while (true)
    {
        failure_times = 0, test_times = 0, success_times = 0;

        for (i_defect_ram = 0; i_defect_ram < defect_ram_count; i_defect_ram ++)
        {
            //*(defect_ram_list[i_defect_ram]) = TEST_PATTERN;
            memset(defect_ram_list[i_defect_ram], TEST_PATTERN, page_size);
        }

        // flush CPU cache
        Sleep(60000);

        // test result
        for (i_defect_ram = 0; i_defect_ram < defect_ram_count; i_defect_ram ++)
        {
            for (current_page_addr = (unsigned int *)defect_ram_list[i_defect_ram];
                current_page_addr < (unsigned int *)(defect_ram_list[i_defect_ram] + page_size); current_page_addr ++)
            {
                test_times ++;

                if ((*current_page_addr) != TEST_PATTERN)
                {
                    failure_times ++;

                    _tprintf(_T("R:0x%02x=0x%02x\n"), current_page_addr, *current_page_addr);
                    //break;
                }
            }
        }

        success_times = test_times - failure_times;
        printf("Success Ratio=%.1f%% [%.0f/%.0f]\n", 100*success_times/test_times, success_times, test_times);
    }
}

int _tmain(int argc, _TCHAR* argv[])
{
    BOOL result;

    HANDLE hProcess;

    SYSTEM_INFO sys_info;           // useful system information
    ULONG_PTR num_of_pages;         // number of pages to request
    ULONG_PTR num_of_pages_initial; // initial number of pages requested
    ULONG_PTR *a_PFNs;              // page info; holds opaque data
    PVOID lp_mem_reserved;          // AWE window
    int PFN_array_size;             // memory to request for PFN array

    MEMORYSTATUSEX memstatex;

    unsigned int defect_PFN_index;
    int i_defect_ram;
    unsigned char *good_ram_base, *good_ram_top;
    ULONG_PTR good_ram_len;
    ULONG_PTR *good_a_PFNs;

    GetSystemInfo(&sys_info);       // fill the system information structure
    _tprintf(_T("CPU Count=%d, Page Size=%d\n"), sys_info.dwNumberOfProcessors, sys_info.dwPageSize);

    // calculate how much memory to alloc
    memstatex.dwLength = sizeof (memstatex);
    GlobalMemoryStatusEx (&memstatex);
    _tprintf(_T("Physical Free=%d MB\n"), memstatex.ullAvailPhys/KILO/KILO);

    memory_to_request = memstatex.ullAvailPhys - PERSEVERED_MEMORY;

    if (memory_to_request > MAX_ALLOC_MEMORY)
    {
        memory_to_request = MAX_ALLOC_MEMORY;
    }
    _tprintf(_T("Memory to Request=%d MB\n"), memory_to_request/KILO/KILO);

    hProcess = GetCurrentProcess();

    // calculate the size of the user PFN array:
    page_size = sys_info.dwPageSize;
    num_of_pages = memory_to_request/page_size;
    PFN_array_size = num_of_pages*sizeof(ULONG_PTR);

    a_PFNs = (ULONG_PTR *)HeapAlloc(GetProcessHeap(), 0, PFN_array_size);

    if (a_PFNs == NULL) 
    {
        _tprintf (_T("Failed to allocate on heap.\n"));
        return -1;
    }

    // enable the privilege:
    acquire_lockpage_privilege(hProcess);

    // allocate the physical memory.
    num_of_pages_initial = num_of_pages;
    result = AllocateUserPhysicalPages(hProcess, &num_of_pages, a_PFNs);
    if(result != TRUE)
    {
        _tprintf(_T("Cannot allocate physical pages, error %u.\n"), GetLastError());
        return -1;
    }

    if(num_of_pages_initial != num_of_pages)
    {
        _tprintf(_T("Allocated only %p pages.\n"), num_of_pages);
        return -1;
    }

    // reserve the virtual memory:
    lp_mem_reserved = VirtualAlloc(NULL, memory_to_request, MEM_RESERVE | MEM_PHYSICAL, PAGE_READWRITE);
    if(lp_mem_reserved == NULL) 
    {
        _tprintf(_T("Cannot reserve memory, error %u.\n"), GetLastError());
        return -1;
    }

    // map the physical memory into the window:
    result = MapUserPhysicalPages(lp_mem_reserved, num_of_pages, a_PFNs);
    if(result != TRUE)
    {
        _tprintf(_T("MapUserPhysicalPages failed, error %u.\n"), GetLastError());
        return -1;
    }

    // test memory now:
    result = detect_defect_ram(lp_mem_reserved, num_of_pages);
    if (result != TRUE)
    {
        _tprintf(_T("Defect RAM Count=%d, Size=%d kB\n"), defect_ram_count, page_size*defect_ram_count/KILO);
    }
    else
    {
        _tprintf(_T("No Defect RAM Detected!\n"));
        return 0;
    }

    // release the good memory:
    good_ram_base = (unsigned char *)lp_mem_reserved;
    for (i_defect_ram = 0; i_defect_ram <= defect_ram_count; i_defect_ram ++)
    {
        if (i_defect_ram < defect_ram_count)
        {
            good_ram_top = defect_ram_list[i_defect_ram];
        }
        else
        { // last entry:
            good_ram_top = ((unsigned char *)lp_mem_reserved + memory_to_request);  // in bytes
        }
        good_ram_len = (good_ram_top - good_ram_base)/page_size;
        
        if (good_ram_len > 0)
        {
            // unmap the physical memory:
            result = MapUserPhysicalPages((void *)good_ram_base, good_ram_len, NULL);
            if(result != TRUE)
            {
                _tprintf(_T("MapUserPhysicalPages failed, error %u.\n"), GetLastError());
                return -1;
            }

            // free the physical pages:
            defect_PFN_index = (good_ram_base - (unsigned char *)lp_mem_reserved)/page_size;
            good_a_PFNs = a_PFNs + defect_PFN_index;
            result = FreeUserPhysicalPages(hProcess, &good_ram_len, good_a_PFNs);
            if (result != TRUE)
            {
                _tprintf(_T("Cannot free physical pages, error %u.\n"), GetLastError());
                return -1;
            }
        }

        good_ram_base = defect_ram_list[i_defect_ram] + page_size;
    }

    // free up ram
    result = HeapFree(GetProcessHeap(), 0, a_PFNs);
    if (result != TRUE)
    {
        _tprintf(_T("Failed to free heap, error %u.\n"), GetLastError());
        return -1;
    }

    test_defect_ram();

    return 0;
}

BOOL acquire_lockpage_privilege(HANDLE hProcess)
{
    BOOL result;
    
    TOKEN_PRIVILEGES tp;
    HANDLE token;

    // Open the token:
    result = OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &token);
    if(result != TRUE ) 
    {
        _tprintf(_T("Cannot open process token.\n"));
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Get the LUID:
    result = LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &(tp.Privileges[0].Luid));
    if(result != TRUE) 
    {
        _tprintf(_T("Cannot get privilege for %s.\n"), SE_LOCK_MEMORY_NAME);
        return FALSE;
    }

    // Adjust the privilege:
    result = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);
    if(result != TRUE) 
    {
        _tprintf(_T("Cannot adjust token privileges, error %u.\n"), GetLastError());
        return FALSE;
    } 
    else 
    {
        DWORD err_num = GetLastError();
        if(err_num == ERROR_NOT_ALL_ASSIGNED) 
        {
            _tprintf(_T("Cannot enable the SE_LOCK_MEMORY_NAME privilege, error %u.\n"), err_num);
            return FALSE;
        }
    }

    CloseHandle(token);

    return TRUE;
}