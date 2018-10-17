/*
 * Copyright (c) 2018 Starship Technologies, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "bag_rdr.hpp"

static bool print_ts_range(const char* bag)
{
    bag_rdr rdr;
    auto open_res = rdr.open_detailed(bag);
    if (!open_res) {
        fprintf(stderr, "failed to open bag '%s': %s\n", bag, open_res.err().c_str());
        return false;
    }

    printf("%u.%09u\n", rdr.start_timestamp().secs, rdr.start_timestamp().nsecs);
    printf("%u.%09u\n", rdr.end_timestamp().secs, rdr.end_timestamp().nsecs);
    return true;
}

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <bagfile>\n", argv[0]);
        return -1;
    }
    const char* const bag_file = argv[1];
    return print_ts_range(bag_file) ? 0 : 1;
}
