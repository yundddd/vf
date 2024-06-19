#include <iostream>

int main() {
  std::cout << "victim binary is running!" << std::endl;
  // Keeps the victim long running so we can inspect various
  // runtime attributes of this program after being injected
  // with a virus.
  while(1);
  return 0;
}
