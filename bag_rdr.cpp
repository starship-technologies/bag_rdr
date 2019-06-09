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

#include "common/array_view.hpp"
#include "common/file_handle.hpp"
#include "common/string_view.hpp"
#include "common/common_timestamp.hpp"
#include "common/common_optional.hpp"

#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <numeric>

#include <bzlib.h>
#ifdef BAG_RDR_USE_SYSTEM_LZ4
#include <lz4frame.h>
#else
#include <roslz4/lz4s.h>
#endif

using common::result;
using common::ok;
using common::unix_err;

static bool assert_print_base(bool result, const char* const statement)
{
    if (!result)
        fprintf(stderr, "bag_rdr: assertion failed: (%s)\n", statement);

    return result;
}
static bool assert_print_base_value(bool result, const char* const statement, size_t actual_value)
{
    if (!result)
        fprintf(stderr, "bag_rdr: assertion failed: (%s) [value was %zu]\n", statement, actual_value);

    return result;
}
#define assert_print(statement) (assert_print_base(statement, #statement))
#define assert_printv(statement, actual_value) (assert_print_base_value(statement, #statement, actual_value))

template <typename T>
bool extract_type(common::array_view<const char> from, T& to)
{
    if (from.size() < sizeof(T))
        return false;
    to = *reinterpret_cast<const T*>(from.data());
    return true;
}

template <>
bool extract_type<common::string_view>(common::array_view<const char> from, common::string_view& to)
{
    to = common::string_view{from};
    return true;
}

template <typename T>
common::array_view<const char> extract_advance(common::array_view<const char> from, T& to)
{
    if (!extract_type(from, to))
        return {};
    return from.advance(sizeof(T));
}

static common::array_view<const char> extract_len_memory(common::array_view<const char> from)
{
    uint32_t byte_count;
    if (!extract_type<uint32_t>(from, byte_count))
        return {};
    const auto contained = from.advance(sizeof(uint32_t)).head(byte_count);
    if (contained.end() > from.end())
        return {};

    return contained;
}

struct record
{
    common::array_view<const char> real_range;
    common::array_view<const char> memory_header;
    common::array_view<const char> memory_data;
    record(common::array_view<const char> memory_range)
    {
        if (!memory_range.size())
            return;
        if (!assert_printv(memory_range.size() >= sizeof(uint32_t), memory_range.size()))
            return;

        memory_header = extract_len_memory(memory_range);

        if (!memory_header.size())
            return;

        common::array_view<const char> data_block {memory_header.end(), memory_range.end()};

        memory_data = extract_len_memory(data_block);

        if (!assert_print(memory_data.size()))
            return;

        real_range = {memory_range.begin(), memory_data.end()};
    }
    bool is_null_record() const
    {
        return (real_range.size() == 0);
    }
};

struct header
{
    common::array_view<const char> real_range;
    common::string_view name, value;
    header(common::array_view<const char> memory_range)
    {
        common::string_view inner {extract_len_memory(memory_range)};
        if (!inner.size())
            return;
        real_range = {memory_range.begin(), inner.end()};
        auto sep = std::find(inner.begin(), inner.end(), '=');
        name = {inner.begin(), sep};
        value = {sep+1, inner.end()};
    }
    enum class op
    {
        BAG_HEADER   = 0x03,
        CHUNK        = 0x05,
        CONNECTION   = 0x07,
        MESSAGE_DATA = 0x02,
        INDEX_DATA   = 0x04,
        CHUNK_INFO   = 0x06,

        UNSET        = 0xff,
    };
    static const char* op_string(op bag_op)
    {
        switch (bag_op) {
          case op::BAG_HEADER:   return "bag_header";
          case op::CHUNK:        return "chunk";
          case op::CONNECTION:   return "connection";
          case op::MESSAGE_DATA: return "message_data";
          case op::INDEX_DATA:   return "index_data";
          case op::CHUNK_INFO:   return "chunk_info";

          case op::UNSET:        return "<op_unset>";
        }
        return "<op_invalid>";
    }
};

struct headers
{
    common::array_view<const char> memory_range;
    headers(common::array_view<const char> memory_range)
    : memory_range{memory_range}
    { }
    struct iterator
    {
        common::array_view<const char> remaining;
        header current;
        iterator(common::array_view<const char> remaining)
        : remaining(remaining)
        , current(remaining)
        {
        }
        const header& operator*() const
        {
            return current;
        }
        const header* operator->() const
        {
            return &current;
        }
        iterator operator++()
        {
            if (!current.real_range.size())
                remaining = {};
            else
                remaining = {current.real_range.end(), remaining.end()};
            current = remaining;
            return *this;
        }
        bool operator!=(const iterator& other)
        {
            return remaining != other.remaining;
        }
    };
    iterator begin() const
    {
        return iterator{memory_range};
    }
    iterator end() const
    {
        return iterator{{}};
    }
    template <typename T>
    size_t extract_headers_inner(const header& hdr, const char* field, common::optional<T>& t)
    {
        if (hdr.name != field)
            return 0;
        T val;
        if (extract_type(hdr.value, val)) {
            t = std::move(val);
        }
        return 1;
    }
    template <typename T, typename... Ts>
    size_t extract_headers_inner(const header& hdr, const char* field, common::optional<T>& t, Ts&... remaining_string_type_pairs)
    {
        return extract_headers_inner(hdr, field, t) || extract_headers_inner(hdr, remaining_string_type_pairs...);
    }
    template <typename... Ts>
    size_t extract_headers(Ts&... string_type_pairs)
    {
        size_t count_filled = 0;
        enum { TOTAL_PAIR_COUNT = sizeof...(string_type_pairs)/2 };
        for (const header& h: *this) {
            count_filled += extract_headers_inner(h, string_type_pairs...);
            if (count_filled == TOTAL_PAIR_COUNT)
                break;
        }
        return count_filled;
    }
};

struct chunk_info
{
    common::timestamp start_timestamp, end_timestamp;
    int32_t message_count;
};

struct chunk
{
    chunk(record r);
    common::array_view<const char> outer_memory;
    common::array_view<const char> memory;
    common::array_view<const char> uncompressed;
    std::vector<char> uncompressed_buffer;
    int32_t uncompressed_size = 0;
    chunk_info info;

    enum chunk_type {
        NORMAL,
        BZ2,
        LZ4,
    } type;

    bool decompress();
    common::array_view<const char> get_uncompressed()
    {
        if (uncompressed.size())
            return uncompressed;
        if (decompress())
            return uncompressed;
        return common::array_view<const char>{};
    }
};


struct index_record
{
    uint32_t time_secs;
    uint32_t time_nsecs;
    int32_t offset;
    common::timestamp to_stamp() const { return common::timestamp{time_secs, time_nsecs}; }
} __attribute__((packed));

struct index_block
{
    common::array_view<const char> memory;
    chunk* into_chunk;
    size_t count() const { return memory.size() / sizeof(index_record); }
    common::array_view<const index_record> as_records() const
    {
        return common::array_view<const index_record>{reinterpret_cast<const index_record*>(memory.data()), count()};
    }
};

struct connection_data
{
    common::string_view topic, type, md5sum, message_definition;
    common::string_view callerid;
    bool latching = false;

    connection_data() = default;
    connection_data(common::array_view<const char> memory)
    {
        common::optional<common::string_view> c_topic, c_type, c_md5sum, c_message_definition, c_callerid, c_latching;
        headers{memory}.extract_headers("topic", c_topic, "type", c_type, "md5sum", c_md5sum,
                                        "message_definition", c_message_definition, "callerid", c_callerid,
                                        "latching", c_latching);
        // The inner topic only applies for mapped topics
        if (!assert_print(c_type && c_md5sum && c_message_definition))
            return;
        if (c_topic)
            topic = c_topic.get();
        type = c_type.get();
        md5sum = c_md5sum.get();
        message_definition = c_message_definition.get();
        callerid = c_callerid.get_or({});
        latching = c_latching && (c_latching.get() == "1");
    }
};

struct bag_rdr::connection_record
{
    std::vector<index_block> blocks;
    common::string_view      topic;
    connection_data          data;
};

chunk::chunk(record r)
: outer_memory(r.real_range)
, memory(r.memory_data)
, info{.start_timestamp={}, .end_timestamp={}, .message_count=0}
{
    common::optional<int32_t> size;
    common::optional<common::string_view> compression_string;
    headers{r.memory_header}.extract_headers("size", size, "compression", compression_string);

    if (!assert_print(size && compression_string))
        return;

    if (!assert_print((size.get() > 64) && (size.get() < 1*1024*1024*1024)))
        return;

    if (compression_string == "none") {
        type = NORMAL;
        uncompressed = memory;
    } else if (compression_string == "bz2") {
        type = BZ2;
        uncompressed_size = size.get();
    } else if (compression_string == "lz4") {
        type = LZ4;
        uncompressed_size = size.get();
    } else {
        fprintf(stderr, "chunk: unknown compression type '%.*s'\n", int(compression_string->size()), compression_string->data());
        return;
    }
}

#ifdef BAG_RDR_USE_SYSTEM_LZ4

struct lz4f_ctx
{
    LZ4F_decompressionContext_t ctx{nullptr};
    ~lz4f_ctx() {
        if (ctx)
            LZ4F_freeDecompressionContext(ctx);
    }
    operator LZ4F_decompressionContext_t() {
        return ctx;
    }
};

static bool s_decompress_lz4(common::array_view<const char> memory, common::array_view<char> to)
{
    lz4f_ctx ctx;
    LZ4F_errorCode_t code = LZ4F_createDecompressionContext(&ctx.ctx, LZ4F_VERSION);
    if (LZ4F_isError(code))
        return code;
    while (memory.size() && to.size()) {
        size_t dest_size = to.size();
        size_t src_size = memory.size();
        size_t ret = LZ4F_decompress(ctx,
                  (void*)     to.begin(), &dest_size,
            (const void*) memory.begin(), &src_size,
            nullptr);
        if (LZ4F_isError(ret)) {
            fprintf(stderr, "chunk::decompress: lz4 decompression returned %zu, expected %zu\n", ret, to.size());
            return false;
        }
        memory = memory.advance(src_size);
        to = to.advance(dest_size);
    }
    if (memory.size() || to.size())
        fprintf(stderr, "chunk::decompress: lz4 decompression left %zu/%zu bytes in buffer\n", memory.size(), to.size());
    return (memory.size() == 0) && (to.size() == 0);
}
#else
static bool s_decompress_lz4(common::array_view<const char> memory, common::array_view<char> to)
{
    unsigned int dest_len = to.size();
    int lz4_ret = roslz4_buffToBuffDecompress((char*)memory.data(), memory.size(),
                                              to.data(), &dest_len);
    if (lz4_ret != ROSLZ4_OK) {
        fprintf(stderr, "chunk::decompress: lz4 decompression returned %d, expected %zu\n", lz4_ret, to.size());
        return false;
    }
    return true;
}
#endif

bool chunk::decompress()
{
    if (!assert_print((type == BZ2) || (type == LZ4)))
        return false;

    uncompressed_buffer.resize(uncompressed_size);

    switch (type) {
        case BZ2: {
            const int bzapi_small = 0;
            const int bzapi_verbosity = 0;
            unsigned int dest_len = uncompressed_buffer.size();
            int bzip2_ret = BZ2_bzBuffToBuffDecompress(uncompressed_buffer.data(), &dest_len,
                                                       (char*) memory.data(), memory.size(),
                                                       bzapi_small,
                                                       bzapi_verbosity);

            if (bzip2_ret != BZ_OK) {
                fprintf(stderr, "chunk::decompress: bzip2 decompression returned %d\n", bzip2_ret);
                return false;
            }
            break;
        }
        case LZ4: {
            if (!s_decompress_lz4(memory, uncompressed_buffer))
                return false;
        }
        case NORMAL: break;
    }

    uncompressed = uncompressed_buffer;
    return true;
}

struct mmap_handle_t
{
    common::array_view<char> memory;
    mmap_handle_t& operator=(mmap_handle_t&& other)
    {
        std::swap(memory, other.memory);
        return *this;
    }
    ~mmap_handle_t()
    {
        if (memory.size()) {
            if (::munmap(memory.data(), memory.size()) != 0)
                fprintf(stderr, "bag_rdr: failed munmap (%m)\n");
        }
    }
};

struct bag_rdr::priv
{
    std::string filename;
    common::file_handle file_handle;
    mmap_handle_t mmap_handle;
    common::array_view<const char> memory;
    common::string_view version_string;
    common::array_view<const char> content;

    std::vector<connection_record> connections;
    std::vector<chunk> chunks;
};

bag_rdr::bag_rdr()
: d(new priv)
{
}

bag_rdr::~bag_rdr()
{
    delete d;
}

bool bag_rdr::open(const char* filename)
{
    return open_detailed(filename).is_ok();
}

result<ok, unix_err> bag_rdr::open_detailed(const char* filename)
{
    result_try(internal_map_file(filename));
    if (!internal_read_initial().size()) {
        return unix_err{EFAULT};
    }
    if (!internal_load_records()) {
        return unix_err{ESPIPE};
    }
    return ok{};
}

result<ok, unix_err> bag_rdr::open_memory(array_view<const char> memory)
{
    d->memory = memory;
    d->filename = "<memory>";
    if (!internal_read_initial().size()) {
        return unix_err{EFAULT};
    }
    if (!internal_load_records()) {
        return unix_err{ESPIPE};
    }
    return ok{};
}

result<ok, unix_err> bag_rdr::internal_map_file(const char* filename)
{
    result_try(d->file_handle.open(filename));

    size_t file_size = d->file_handle.size();
    if (!file_size)
        return unix_err{ERANGE};

    void* ptr = ::mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, ::fileno(d->file_handle.file), 0);
    if (ptr == MAP_FAILED) {
        fprintf(stderr, "bag_rdr: mmap of file '%s' failed (%m)\n", filename);
        return unix_err::current();
    }
    d->memory = common::array_view<const char>{reinterpret_cast<const char*>(ptr), file_size};
    d->mmap_handle = mmap_handle_t{common::array_view<char>{(char*)ptr, file_size}};
    d->filename = filename;

    return ok{};
}

common::string_view bag_rdr::internal_read_initial()
{
    if (!assert_print(d->memory.size()))
        return {};

    common::string_view str {d->memory};

    const common::string_view bag_magic_prefix {"#ROSBAG V"};

    if (!assert_print(str.begins_with(bag_magic_prefix)))
        return {};

    common::string_view version_block = str.advance(bag_magic_prefix.size());

    const void* newline_found = ::memchr(const_cast<char*>(version_block.data()), '\n', std::min<size_t>(str.size(), 256));
    if (!assert_print(newline_found))
        return {};

    d->version_string = {version_block.data(), (const char*) newline_found};
    d->content = {((const char*) newline_found) + 1, d->memory.end()};

    return d->version_string;
}


bool bag_rdr::internal_load_records()
{
    common::array_view<const char> remaining = d->content;

    bool had_chunk = false;
    // offset into file of first record after chunk/index_data
    using lld_t = long long;
    int64_t index_pos = 0;
    while (remaining.size()) {
        record r{remaining};
        if (r.is_null_record()) {
            const int64_t pos = remaining.data() - d->memory.begin();
            if (pos < index_pos) {
                remaining = {d->memory.data() + index_pos, d->memory.end()};
                continue;
            }
            fprintf(stderr, "load_records: null record past bag_hdr.index_pos (%lld > %lld)\n", lld_t(pos), lld_t(index_pos));
            return false;
        }
        headers hdrs{r.memory_header};
        common::optional<int8_t> op_hdr;
        hdrs.extract_headers("op", op_hdr);

        remaining = remaining.advance(r.real_range.size());

        if (!assert_print(bool(op_hdr)))
            return false;
        header::op op = header::op(op_hdr.get());

        switch (op) {
          case header::op::BAG_HEADER: {
            common::optional<int32_t> conn_count, chunk_count;
            common::optional<int64_t> c_index_pos;
            hdrs.extract_headers("conn_count", conn_count, "chunk_count", chunk_count, "index_pos", c_index_pos);
            if (!assert_print(conn_count && chunk_count && c_index_pos))
                return false;
            // the empty bag
            if ((conn_count.get() == 0) && (chunk_count.get() == 0))
                return true;
            if (!assert_print((conn_count.get() > 0) && (chunk_count.get() > 0) && (c_index_pos.get() > 64)))
                return false;
            d->connections.resize(conn_count.get());
            d->chunks.reserve(chunk_count.get());
            index_pos = *c_index_pos;
            break;
          }
          case header::op::CHUNK: {
            had_chunk = true;
            d->chunks.emplace_back(r);
            break;
          }
          case header::op::INDEX_DATA: {
            if (!assert_print(had_chunk))
                return false;
            common::optional<int32_t> ver, conn, count;
            hdrs.extract_headers("ver", ver, "conn", conn, "count", count);
            if (!assert_print(ver && conn && count))
                continue;
            assert_printv(count.get()*sizeof(index_record) == r.memory_data.size(), count.get()*sizeof(index_record));
            const int32_t conn_id = conn.get();
            if (!assert_print((conn_id >= 0) && (size_t(conn_id) < d->connections.size())))
                continue;
            d->connections[conn.get()].blocks.emplace_back(index_block{.memory=r.memory_data, .into_chunk=&d->chunks.back()});
            break;
          }
          case header::op::CONNECTION: {
            common::optional<int32_t> conn;
            common::optional<common::string_view> topic;
            hdrs.extract_headers("conn", conn, "topic", topic);
            if (!assert_print(conn && topic))
                continue;
            const int32_t conn_id = conn.get();
            if (!assert_print((conn_id >= 0) && (size_t(conn_id) < d->connections.size())))
                continue;

            connection_data data{r.memory_data};
            if (!data.md5sum.size())
                continue;
            d->connections[conn_id].topic = topic.get();
            d->connections[conn_id].data = data;
            break;
          }
          case header::op::MESSAGE_DATA: {
            break;
          }
          case header::op::CHUNK_INFO: {
            common::optional<int32_t> ver, chunk_pos, count;
            common::optional<common::timestamp> start_time, end_time;
            hdrs.extract_headers("ver", ver, "chunk_pos", chunk_pos, "count", count, "start_time", start_time, "end_time", end_time);
            if (!assert_print(ver && chunk_pos && count && start_time && end_time))
                continue;
            auto chunk_it = std::find_if(d->chunks.begin(), d->chunks.end(), [this, &chunk_pos] (const chunk& c) {
                return (c.outer_memory.data() - d->memory.data()) == chunk_pos.get();
            });
            if (!assert_print(chunk_it != d->chunks.end()))
                continue;
            assert_print(chunk_it->info.message_count == 0);
            chunk_it->info = chunk_info{start_time.get(), end_time.get(), count.get()};
            static_assert(sizeof(common::timestamp) == sizeof(int64_t), "size of common::timestamp not binary compatible with bag timestamps");
            break;
          }
          case header::op::UNSET:
          default:
             fprintf(stderr, "bag_rdr: Unknown record operation 0x%hhx\n", int8_t(op));
        }
    }
    return true;
}

common::timestamp bag_rdr::start_timestamp() const
{
    if (d->chunks.empty())
        return common::timestamp{};
    return d->chunks.front().info.start_timestamp;
}

common::timestamp bag_rdr::end_timestamp() const
{
    if (d->chunks.empty())
        return common::timestamp{};
    return d->chunks.back().info.end_timestamp;
}

size_t bag_rdr::size() const
{
    size_t ret = 0;
    for (const connection_record& c: d->connections)
        for (const index_block& block: c.blocks)
            ret += block.count();
    return ret;
}

size_t bag_rdr::file_size() const
{
    return d->file_handle.size();
}


bag_rdr::view::view(const bag_rdr& rdr)
: rdr(rdr)
{
}

void bag_rdr::view::ensure_indices()
{
    if (m_connections.size())
        return;
    m_connections.reserve(rdr.d->connections.size());
    for (auto& conn : rdr.d->connections)
        m_connections.push_back(&conn);
}

bag_rdr::view bag_rdr::get_view() const
{
    return view{*this};
}

static void add_connection_ptr(std::vector<bag_rdr::connection_record*>& connection_ptrs, std::vector<bag_rdr::connection_record>& connections, common::string_view topic)
{
    for (bag_rdr::connection_record& conn : connections) {
        if (conn.data.topic.size() && (conn.topic != conn.data.topic)) {
            fprintf(stderr, "bag_rdr: Inner topic [%zu]'%.*s' doesn't match outer '%.*s', not yet handled.\n",
                conn.data.topic.size(), conn.data.topic.sizei(), conn.data.topic.data(),
                conn.topic.sizei(), conn.topic.data());
        }
        if (conn.topic == topic) {
            auto it = std::find(connection_ptrs.begin(), connection_ptrs.end(), &conn);
            if (it != connection_ptrs.end())
                break;
            connection_ptrs.emplace_back(&conn);
        }
    }
}

void bag_rdr::view::set_topics(common::array_view<const std::string> topics)
{
    m_connections.clear();
    m_connections.reserve(topics.size());
    for (const std::string& topic : topics)
        add_connection_ptr(m_connections, rdr.d->connections, topic);
}

void bag_rdr::view::set_topics(array_view<const char*> topics)
{
    m_connections.clear();
    m_connections.reserve(topics.size());
    for (const char* topic : topics)
        add_connection_ptr(m_connections, rdr.d->connections, topic);
}

void bag_rdr::view::set_topics(std::initializer_list<const char*> topics)
{
    m_connections.clear();
    m_connections.reserve(topics.size());
    for (const char* topic : topics)
        add_connection_ptr(m_connections, rdr.d->connections, topic);
}

void bag_rdr::view::set_topics(array_view<common::string_view> topics)
{
    m_connections.clear();
    m_connections.reserve(topics.size());
    for (const common::string_view& topic : topics)
        add_connection_ptr(m_connections, rdr.d->connections, topic);
}

std::vector<common::string_view> bag_rdr::view::present_topics()
{
    ensure_indices();
    std::vector<common::string_view> ret;

    for (const auto& conn : m_connections) {
        common::string_view topic = conn->data.topic;
        auto it = std::find(ret.begin(), ret.end(), topic);
        if (it == ret.end())
            ret.emplace_back(std::move(topic));
    }
    return ret;
}

bool bag_rdr::view::has_topic(common::string_view topic)
{
    ensure_indices();

    for (const auto& conn : m_connections) {
        if (conn->data.topic == topic)
            return true;
    }
    return false;
}

void bag_rdr::view::for_each_connection(const std::function<void (const connection_data& data)>& fn)
{
    ensure_indices();
    for (const auto& conn : m_connections) {
        fn(connection_data {
            .topic = conn->topic,
            .datatype = conn->data.type,
            .md5sum = conn->data.md5sum,
            .msg_def = conn->data.message_definition,
            .callerid = conn->data.callerid,
            .latching = conn->data.latching,
        });
    }
}

static bool increment_pos_ref(const bag_rdr::connection_record& conn, bag_rdr::view::iterator::pos_ref& pos)
{
    assert_print(pos.block != -1);
    const index_block& block = conn.blocks[pos.block];
    if (++pos.record == int(block.as_records().size())) {
        pos.record = 0;
        if (++pos.block == int(conn.blocks.size())) {
            pos.block = -1;
            return false;
        }
    }
    return true;
}

struct lowest_set
{
    common::timestamp stamp;
    int index = -1;
    explicit operator bool() const
    {
        return index >= 0;
    }
};

static common::timestamp pos_ref_timestamp(const bag_rdr::view::iterator& it, int32_t index)
{
    const bag_rdr::view::iterator::pos_ref& pos = it.connection_positions[index];
    const bag_rdr::connection_record& conn = *it.v.m_connections[index];
    const index_block& block = conn.blocks[pos.block];
    const index_record& record = block.as_records()[pos.record];
    return record.to_stamp();
}

static void iterator_construct_connection_order(bag_rdr::view::iterator& it)
{
    it.connection_order.clear();
    for (size_t i = 0; i < it.connection_positions.size(); ++i) {
        const bag_rdr::view::iterator::pos_ref& pos = it.connection_positions[i];
        if (pos.block == -1)
            continue;
        const bag_rdr::connection_record& conn = *it.v.m_connections[i];
        if ((size_t)pos.block >= conn.blocks.size()) {
            fprintf(stderr, "bag_rdr: invalid bag: conn index referenced non-existent block (index: %d, conn.blocks.size(): %zu).\n", pos.block, conn.blocks.size());
            continue;
        }
        it.connection_order.emplace_back(int32_t(i));
    }
    std::sort(it.connection_order.begin(), it.connection_order.end(), [&] (int32_t ia, int32_t ib) {
        return pos_ref_timestamp(it, ia) < pos_ref_timestamp(it, ib);
    });
}

// assumes we just consumed connection_order[0]
static void iterator_update_connection_order(bag_rdr::view::iterator& it)
{
    size_t head_index = it.connection_order[0];
    common::timestamp connection_next_stamp = pos_ref_timestamp(it, head_index);
    if (it.v.m_end_time && (connection_next_stamp > it.v.m_end_time)) {
        it.connection_order.erase(it.connection_order.begin());
        return;
    }
    auto elem_above = std::lower_bound(it.connection_order.begin() + 1, it.connection_order.end(), connection_next_stamp, [&] (int32_t index, const common::timestamp& find_stamp) {
        return pos_ref_timestamp(it, index) < find_stamp;
    });
    size_t index_after_first = std::distance(it.connection_order.begin(), elem_above) - 1;
    if (index_after_first == 0)
        return;

    auto pos = std::move(it.connection_order.begin() + 1, elem_above, it.connection_order.begin());
    *pos = head_index;
}

bag_rdr::view::iterator& bag_rdr::view::iterator::operator++()
{
    if (connection_positions.empty())
        return *this;
    const size_t old_head_index = connection_order[0];
    if (increment_pos_ref(*v.m_connections[old_head_index], connection_positions[old_head_index])) {
        iterator_update_connection_order(*this);
    } else {
        connection_order.erase(connection_order.begin());
    }
    if (!connection_order.size()) {
        connection_positions.clear();
    } else {
        const size_t head_index = connection_order[0];
        const connection_record& conn = *v.m_connections[head_index];
        const pos_ref& head = connection_positions[head_index];
        const index_block& block = conn.blocks[head.block];
        common::array_view<const char> chunk_memory = block.into_chunk->get_uncompressed();
        if (!chunk_memory.size()) {
            connection_positions.clear();
            return *this;
        }

    }
    return *this;
}

bag_rdr::view::iterator bag_rdr::view::begin()
{
    ensure_indices();
    return iterator{*this, iterator::constructor_start_tag{}};
}

bag_rdr::view::iterator bag_rdr::view::end()
{
    return iterator{*this};
}

static bag_rdr::view::iterator::pos_ref find_starting_position(const bag_rdr::view& v,
                                                               const bag_rdr::connection_record& conn)
{
    bag_rdr::view::iterator::pos_ref pos{0, 0};
    for (; pos.block < int(conn.blocks.size()); ++pos.block) {
        const index_block& block = conn.blocks[pos.block];
        const auto block_records = block.as_records();
        for (pos.record = 0; pos.record < int(block_records.size()); ++pos.record) {
            const index_record& record = block_records[pos.record];
            if (v.m_end_time && (record.to_stamp() > v.m_end_time)) {
                pos.block = -1;
                return {-1, 0};
            }
            if (record.to_stamp() >= v.m_start_time)
                return pos;
        }
    }
    return {-1, 0};
}

bag_rdr::view::iterator::iterator(const bag_rdr::view& v, constructor_start_tag)
: v(v)
{
    connection_positions.resize(v.m_connections.size(), pos_ref{0, 0});
    if (v.m_start_time) {
        for (size_t i = 0; i < connection_positions.size(); ++i) {
            const connection_record& conn = *v.m_connections[i];
            connection_positions[i] = find_starting_position(v, conn);
        }
    }
    iterator_construct_connection_order(*this);
    if (!connection_order.size()) {
        connection_positions.clear();
        return;
    }

    const size_t head_index = connection_order[0];

    const connection_record& conn = *v.m_connections[head_index];
    const pos_ref& head = connection_positions[head_index];
    const index_block& block = conn.blocks[head.block];
    common::array_view<const char> chunk_memory = block.into_chunk->get_uncompressed();
    if (!chunk_memory.size()) {
        connection_positions.clear();
    }
}

bag_rdr::view::message bag_rdr::view::iterator::operator*() const
{
    if (!assert_print(connection_order.size() > 0))
        abort();
    const size_t head_index = connection_order[0];
    const connection_record& conn = *v.m_connections[head_index];
    const pos_ref& head = connection_positions[head_index];
    const index_block& block = conn.blocks[head.block];
    const index_record& rec = block.as_records()[head.record];
    common::array_view<const char> chunk_memory = block.into_chunk->get_uncompressed();
    if (!chunk_memory.size())
        abort();
    common::array_view<const char> record_memory = chunk_memory.advance(rec.offset);
    record r{record_memory};

    return message{.stamp=rec.to_stamp(), .md5=conn.data.md5sum, .message_data_block=r.memory_data, .connection=&conn};
}

common::string_view bag_rdr::view::message::topic() const
{
    return connection->topic;
}

common::string_view bag_rdr::view::message::data_type() const
{
    return connection->data.type;
}

common::string_view bag_rdr::view::message::message_definition() const
{
    return connection->data.message_definition;
}

bool bag_rdr::view::message::is_latching() const
{
    return connection->data.latching;
}

