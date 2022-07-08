#include "common/macros.hh"
#include "std/string.hh"
#include "std/sys.hh"

int main(int argc, char* argv[], char* env[]) {
  write(1, argv[0], strlen(argv[0]));
  write(1, env[0], strlen(env[0]));

  return 0;
}
