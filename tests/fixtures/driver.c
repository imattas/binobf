extern int binobf_fixture_bias;
int binobf_fixture_add(int left, int right);
int binobf_fixture_accumulate(int limit);

int main(void) {
    if (binobf_fixture_add(2, 3) != 8) {
        return 1;
    }
    if (binobf_fixture_accumulate(5) != 13) {
        return 2;
    }
    binobf_fixture_bias = 4;
    if (binobf_fixture_add(2, 3) != 9) {
        return 3;
    }
    return 0;
}
