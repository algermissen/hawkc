#ifndef TEST_H
#define TEST_H 1

#include <strings.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RUNTEST(p,f) do { printf("  %s:",(p));  int r = f(); if(r != 0 ) { printf(#f " failed\n"); return r; } else { printf(#f " ok\n"); } } while(0)

#define EXPECT_TRUE(exp) do { if(! (exp) ) { printf("Test failed in %s line %d: expected " #exp " to be true, but was false\n", __FILE__ , __LINE__ ); return 1; } } while(0)
#define EXPECT_STR_EQUAL(a,b) do { if( (strlen((a)) != strlen((b))) || (strncmp((a) , (b) , strlen((b))) != 0) ) { printf("Test failed in %s line %d: expected \"%s\" but got \"%s\"\n", __FILE__ , __LINE__,(a),(b) ); return 1; } } while(0)
#define EXPECT_BYTE_EQUAL(a,b,n) do { if( memcmp((a) , (b) , (n) ) != 0 ) { printf("Test failed in %s line %d: \n", __FILE__ , __LINE__ ); return 1; } } while(0)

#define EXPECT_INT_EQUAL(a,b) do { if( (a) != (b) ) { printf("Test failed in %s line %d: expected %d but got %d\n", __FILE__ , __LINE__,(a),(b) ); return 1; } } while(0)

#define EXPECT_RETVAL(expected,actual,ctx) do { if( (expected)  != (actual) ) { printf("Test failed in %s line %d: expected " #actual "=" #expected ", but context has %s\n", __FILE__ , __LINE__ , hawkc_get_error( (ctx)) ); return 1; } } while(0)










#ifdef __cplusplus
} // extern "C"
#endif


#endif /* !defined TEST_H */

