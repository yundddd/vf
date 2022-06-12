

#include "common/file_descriptor.hh"
using namespace vt;
int main(){
    common::FileDescriptor f("/tmp/a", 1 | 64);
    return 0;
}