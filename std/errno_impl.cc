int errno;
void set_errno(int e) { errno = e; }
void save_errno(int& s) { s = errno; }