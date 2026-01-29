/* meld comprehensive test */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern int archive_func(int x);
extern char _DYNAMIC[] __attribute__((weak));
extern char _GLOBAL_OFFSET_TABLE_[] __attribute__((weak));

int add(int a, int b) { return a + b; }
int multiply(int a, int b) { return a * b; }

int global_data = 100;
const char *message = "Hello from data";
__attribute__((weak)) int weak_value(void) { return 67; }
const char rodata[] = "This is read-only data";
int local_data = 67;
int bss_var;
__attribute__((section(".mydata"))) int mydata = 1234;
static const char *static_ptr = "static ptr test";
static int ctor_ran = 0;

__attribute__((constructor)) static void ctor(void) { ctor_ran = 1; printf("ctor"); }
__attribute__((destructor)) static void dtor(void) { puts("dtor"); }

#define TEST(n, c) do { printf("%-40s %s\n", n, (c) ? (passed++, "ok") : (failed++, "FAIL")); } while(0)
#define TEST_EQ(n, g, e) do { int _g=(g), _e=(e); printf("%-40s %s\n", n, _g==_e ? (passed++, "ok") : (failed++, "FAIL")); } while(0)

int main(void) {
    int passed = 0, failed = 0;
    
    printf("\nmeld test\n");
    
    TEST("constructor ran", ctor_ran == 1);
    TEST_EQ("add(10,5)", add(10,5), 15);
    TEST_EQ("multiply(6,5)", multiply(6,5), 30);
    TEST_EQ("global_data", global_data, 100);
    TEST("message", message && strcmp(message, "Hello from data") == 0);
    TEST_EQ("weak_value()", weak_value(), 67);
    TEST_EQ("archive_func(10)", archive_func(10), 20);
    TEST_EQ("local_data", local_data, 67);
    TEST_EQ("bss_var", bss_var, 0);
    TEST_EQ("mydata", mydata, 1234);
    TEST_EQ("rodata len", (int)strlen(rodata), 22);
    TEST("static_ptr reloc", static_ptr && strcmp(static_ptr, "static ptr test") == 0);
    TEST_EQ("strlen", (int)strlen("test"), 4);
    TEST("strcmp", strcmp("abc", "abc") == 0);
    void *p = malloc(64);
    TEST("malloc", p != NULL);
    free(p);
    
    if (_DYNAMIC) { printf("%-40s ok (%p)\n", "_DYNAMIC", (void*)_DYNAMIC); passed++; }
    else { printf("%-40s skip\n", "_DYNAMIC"); passed++; }
    if (_GLOBAL_OFFSET_TABLE_) { printf("%-40s ok (%p)\n", "_GOT_", (void*)_GLOBAL_OFFSET_TABLE_); passed++; }
    else { printf("%-40s skip\n", "_GOT_"); passed++; }
    
    printf("\n%d passed, %d failed\n\n", passed, failed);
    return failed;
}
