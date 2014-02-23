
#include <sys/types.h>
#include <stdint.h>

#include "sha1.h"
#include "md5.h"

#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/bigarray.h>
#include <caml/memory.h>
#include <caml/alloc.h>

intnat sha1_size = 20;

CAMLprim value caml_DESU_sha1 (value buffer) {
  CAMLparam1 (buffer);
  CAMLlocal1 (res);
  res = caml_ba_alloc (CAML_BA_UINT8|CAML_BA_C_LAYOUT, 1, NULL, &sha1_size);
  SHA1_CTX *ctx = malloc (sizeof(SHA1_CTX));

  SHA1_Init (ctx);
  SHA1_Update (ctx, Caml_ba_data_val(buffer), Caml_ba_array_val(buffer)->dim[0]);
  SHA1_Final (ctx, (unsigned char *) Caml_ba_data_val(res));

  free (ctx);
  CAMLreturn (res);
}

intnat md5_size = 16;

CAMLprim value caml_DESU_md5 (value buffer) {
  CAMLparam1 (buffer);
  CAMLlocal1 (res);
  res = caml_ba_alloc (CAML_BA_UINT8|CAML_BA_C_LAYOUT, 1, NULL, &md5_size);
  MD5_CTX *ctx = malloc (sizeof(MD5_CTX));

  MD5_Init (ctx);
  MD5_Update (ctx, Caml_ba_data_val(buffer), Caml_ba_array_val(buffer)->dim[0]);
  MD5_Final ((unsigned char *) Caml_ba_data_val(res), ctx);

  free (ctx);
  CAMLreturn (res);
}
