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
#include <numeric>
#include <cstdio>
#include <map>

static bool print_sizes(const char* bag)
{
    bag_rdr rdr;
    auto res = rdr.open_detailed(bag);
    if (!res) {
        fprintf(stderr, "failed to read '%s': %s\n", bag, res.err().c_str());
        return false;
    }

    std::map<common::string_view, std::vector<size_t>> sizes;
    for (auto msg : rdr.get_view()) {
        sizes[msg.topic()].push_back(msg.message_data_block.size());
    }
    printf("topic,count,avg_bytes,total_bytes\n");
    for (const auto& pair : sizes) {
        const auto& vec = pair.second;
        size_t total = std::accumulate(vec.begin(), vec.end(), 0);
        printf("%s,%zu,%zu,%zu\n", pair.first.to_string().c_str(), vec.size(), total / vec.size(), total);
    }
    return true;
}

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <bagfile>\n", argv[0]);
        return -1;
    }
    const char* const bag_file = argv[1];
    return print_sizes(bag_file) ? 0 : 1;
}

