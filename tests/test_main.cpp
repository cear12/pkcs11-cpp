// Catch2 wants CATCH_CONFIG_MAIN compiled exactly once, in its own
// translation unit -- everything else just #includes catch.hpp normally
// and defines TEST_CASE blocks.
#define CATCH_CONFIG_MAIN
#include "catch.hpp"
