int binobf_fixture_bias = 3;

int binobf_fixture_add(int left, int right) {
    return left + right + binobf_fixture_bias;
}

int binobf_fixture_accumulate(int limit) {
    int total = 0;
    for (int value = 0; value < limit; ++value) {
        total += value;
    }
    return total + binobf_fixture_bias;
}
