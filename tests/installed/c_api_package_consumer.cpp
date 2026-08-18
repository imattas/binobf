#include <binobf/c_api.h>

int main() {
    return binobf_version() != nullptr && binobf_version()[0] != '\0' ? 0 : 1;
}
