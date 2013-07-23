#include "common.h"
#include "test.h"
#include "base64url.h"



/*

 Test vectors from http://www.ietf.org/rfc/rfc4648.txt section 10.

 BASE64("") = ""

 BASE64("f") = "Zg=="

 BASE64("fo") = "Zm8="

 BASE64("foo") = "Zm9v"

 BASE64("foob") = "Zm9vYg=="

 BASE64("fooba") = "Zm9vYmE="

 BASE64("foobar") = "Zm9vYmFy"
 */
int test_base64url_encodes_correctly() {

	unsigned char chars[256];
	int len;

	unsigned char b1[] = { 0x66 }; /* "f" */
	unsigned char b2[] = { 0x66, 0x6f }; /* "fo" */
	unsigned char b3[] = { 0x66, 0x6f, 0x6f }; /* "foo" */
	unsigned char b4[] = { 0x66, 0x6f, 0x6f, 0x62 }; /* "foob" */
	unsigned char b5[] = { 0x66, 0x6f, 0x6f, 0x62, 0x61 }; /* "fooba" */
	unsigned char b6[] = { 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72 }; /* "foobar" */
	unsigned char b7[] = { 62, 1, 2, 3, 4, 5, 6, 7, 120, 60, 61, 63, 65, 44, 21, 22, 23,
			24, 30, 31, 32, 45, 92, 93, 94, 95, 80, 81, 82, 83, 84 };

	hawkc_base64url_encode(b1, 0, chars, &len); /* Can't have empty bytes, so we just use len=0 to mimick */
	EXPECT_BYTE_EQUAL((unsigned char *)"", chars,0);
	hawkc_base64url_encode(b1, 1, chars, &len);
	EXPECT_BYTE_EQUAL((unsigned char *)"Zg", chars,2);

	hawkc_base64url_encode(b2, 2, chars, &len);
	EXPECT_BYTE_EQUAL((unsigned char *)"Zm8", chars,3);

	hawkc_base64url_encode(b3, 3, chars, &len);
	EXPECT_BYTE_EQUAL((unsigned char *)"Zm9v", chars,4);

	hawkc_base64url_encode(b4, 4, chars, &len);
	EXPECT_BYTE_EQUAL((unsigned char *)"Zm9vYg", chars,6);

	hawkc_base64url_encode(b5, 5, chars, &len);
	EXPECT_BYTE_EQUAL((unsigned char *)"Zm9vYmE", chars,7);

	hawkc_base64url_encode(b6, 6, chars, &len);
	EXPECT_BYTE_EQUAL((unsigned char *)"Zm9vYmFy", chars,8);

	hawkc_base64url_encode(b7, 31, chars, &len);
	EXPECT_BYTE_EQUAL((unsigned char *)"PgECAwQFBgd4PD0_QSwVFhcYHh8gLVxdXl9QUVJTVA", chars,42);

	return 0;
}

/*

 Test vectors from http://www.ietf.org/rfc/rfc4648.txt section 10.

 BASE64("") = ""

 BASE64("f") = "Zg=="

 BASE64("fo") = "Zm8="

 BASE64("foo") = "Zm9v"

 BASE64("foob") = "Zm9vYg=="

 BASE64("fooba") = "Zm9vYmE="

 BASE64("foobar") = "Zm9vYmFy"
 */
int test_base64url_decodes_correctly() {

	unsigned char bytes[256];
	int len;

	unsigned char b1[] = { 0x66 }; /* "f" */
	unsigned char b2[] = { 0x66, 0x6f }; /* "fo" */
	unsigned char b3[] = { 0x66, 0x6f, 0x6f }; /* "foo" */
	unsigned char b4[] = { 0x66, 0x6f, 0x6f, 0x62 }; /* "foob" */
	unsigned char b5[] = { 0x66, 0x6f, 0x6f, 0x62, 0x61 }; /* "fooba" */
	unsigned char b6[] = { 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72 }; /* "foobar" */
	unsigned char b7[] = { 62, 1, 2, 3, 4, 5, 6, 7, 120, 60, 61, 63, 65, 44, 21, 22, 23,
			24, 30, 31, 32, 45, 92, 93, 94, 95, 80, 81, 82, 83, 84 };

	hawkc_base64url_decode((unsigned char*)"", 0, bytes, &len);
	EXPECT_TRUE(len == 0);

	hawkc_base64url_decode((unsigned char*)"Zg", 2, bytes, &len);
	EXPECT_TRUE(len == 1);
	EXPECT_BYTE_EQUAL(b1, bytes, 1);

	hawkc_base64url_decode((unsigned char*)"Zm8", 3, bytes, &len);
	EXPECT_TRUE(len == 2);
	EXPECT_BYTE_EQUAL(b2, bytes, 2);

	hawkc_base64url_decode((unsigned char*)"Zm9v", 4, bytes, &len);
	EXPECT_TRUE(len == 3);
	EXPECT_BYTE_EQUAL(b3, bytes, 3);

	hawkc_base64url_decode((unsigned char*)"Zm9vYg", 6, bytes, &len);
	EXPECT_TRUE(len == 4);
	EXPECT_BYTE_EQUAL(b4, bytes, 4);

	hawkc_base64url_decode((unsigned char*)"Zm9vYmE", 7, bytes, &len);
	EXPECT_TRUE(len == 5);
	EXPECT_BYTE_EQUAL(b5, bytes, 5);

	hawkc_base64url_decode((unsigned char*)"Zm9vYmFy", 8, bytes, &len);
	EXPECT_TRUE(len == 6);
	EXPECT_BYTE_EQUAL(b6, bytes, 6);

	hawkc_base64url_decode((unsigned char*)"PgECAwQFBgd4PD0_QSwVFhcYHh8gLVxdXl9QUVJTVA", 42,
			bytes, &len);
	EXPECT_TRUE(len == 31);
	EXPECT_BYTE_EQUAL(b7, bytes, 31);

	return 0;
}

int main(int argc, char **argv) {

	RUNTEST(argv[0], test_base64url_encodes_correctly);
	RUNTEST(argv[0], test_base64url_decodes_correctly);

	return 0;
}
