/* Lab-only crypt(3) stub: ASan + libcrypt SIGSEGVs on PASS before the rewrite sink. */
#include <string.h>

char *crypt(const char *key, const char *salt) {
  static char out[256];

  if (key == NULL || salt == NULL) {
    return NULL;
  }
  if (strcmp(key, "labpass") == 0) {
    strncpy(out, salt, sizeof(out) - 1);
    out[sizeof(out) - 1] = '\0';
    return out;
  }
  out[0] = '*';
  out[1] = '\0';
  return out;
}
