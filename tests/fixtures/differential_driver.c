#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

extern int binobf_fixture_bias;
int binobf_fixture_add(int left, int right);
int binobf_fixture_accumulate(int limit);
int binobf_transform_pattern(void);
int binobf_transform_secondary(void);
int binobf_transform_blocks(void);

int main(int argc, char** argv) {
    if (argc != 3) {
        return 64;
    }
    errno = 0;
    char* end = NULL;
    const long parsed = strtol(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0'
        || parsed < INT_MIN || parsed > INT_MAX) {
        return 65;
    }
    const int input = (int)parsed;
    const int biasBefore = binobf_fixture_bias;
    const int added = binobf_fixture_add(input, 11);
    const int accumulated = binobf_fixture_accumulate(input);
    binobf_fixture_bias = (input % 7) + 10;
    const int changed = binobf_fixture_add(2, 3);
    const int pattern = binobf_transform_pattern();
    const int secondary = binobf_transform_secondary();
    const int blocks = binobf_transform_blocks();

    FILE* sideEffect = fopen(argv[2], "wb");
    if (sideEffect == NULL) {
        return 66;
    }
    if (fprintf(sideEffect, "bias_before=%d\nbias_after=%d\nchecksum=%d\n",
                biasBefore, binobf_fixture_bias,
                added + accumulated + changed + pattern + secondary + blocks) < 0
        || fclose(sideEffect) != 0) {
        return 67;
    }
    if (printf("input=%d add=%d accumulate=%d changed=%d pattern=%d secondary=%d blocks=%d\n",
               input, added, accumulated, changed, pattern, secondary, blocks) < 0) {
        return 68;
    }
    return ((input % 5) + 5) % 5;
}
