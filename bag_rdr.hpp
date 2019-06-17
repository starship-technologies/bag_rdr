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

#ifndef BAG_RDR_HPP
#define BAG_RDR_HPP

#include "common/string_view.hpp"
#include "common/common_timestamp.hpp"
#include "common/common_result.hpp"
#include "common/unix_err.hpp"

#include <functional>

#ifndef BAG_RDR_NO_ROS
#include <ros/serialization.h>
#endif

/**
 * A minimal, zero-copy memory-map based ROS
 * bag reader. Only allocates for the decompression
 * buffer in compressed bags, and small vectors
 * of indices for topic selection and iteration.
 */
struct bag_rdr
{
    using timestamp   = common::timestamp;
    using string_view = common::string_view;
    using ok          = common::ok;
    using unix_err    = common::unix_err;
    template <typename T, typename E>
    using result      = common::result<T, E>;
    template <typename T>
    using array_view  = common::array_view<T>;

    bag_rdr();
    ~bag_rdr();
    bool open(const char* filename);
    result<ok, unix_err> open_detailed(const char* filename);
    result<ok, unix_err> open_memory(array_view<const char> memory);

    timestamp start_timestamp() const;
    timestamp end_timestamp() const;
    size_t size() const;
    size_t file_size() const;

    struct view;
    view get_view() const;

    struct message;
    struct connection_record;

    // detail
    result<ok, unix_err> internal_map_file(const char* filename);
    string_view internal_read_initial();
    bool internal_load_records();

    struct priv;
    priv* const d;
};


struct bag_rdr::message
{
#ifndef BAG_RDR_NO_ROS
    template <class T>
    bool to(T& t) const
    {
        if (!is<T>())
            return false;
        ros::serialization::IStream s{(uint8_t*)message_data_block.data(), uint32_t(message_data_block.size())};
        try {
            ros::serialization::deserialize(s, t);
        } catch (const std::exception& e) {
            return false;
        }
        return true;
    }
    template <class T>
    bool is() const
    {
        string_view t_md5sum = ros::message_traits::MD5Sum<T>::value();
        return (t_md5sum == "*") || (t_md5sum == md5);
    }
    // Use for e.g. topic_tools::ShapeShifter
    template <class T>
    void pre_deserialise(T& t) const
    {
        ros::serialization::PreDeserializeParams<T> predes;
        std::map<std::string, std::string> map;
        predes.message = boost::shared_ptr<T>(&t, [] (T*) {});
        predes.connection_header = boost::shared_ptr<T>(&map, [] (std::map<std::string, std::string>*) {});
        map["md5sum"] = md5.to_string();
        map["type"] = data_type().to_string();
        map["message_definition"] = message_definition().to_string();
        map["latching"] = latching_str().to_string();
        ros::serialization::PreDeserialize<T>::notify(predes);
    }
#endif // !defined(BAG_RDR_NO_ROS)

    timestamp stamp;
    string_view topic() const;
    string_view md5;
    string_view data_type() const;
    string_view message_definition() const;
    bool is_latching() const;
    string_view latching_str() const { return is_latching() ? "1" : ""; }

    array_view<const char> message_data_block;
    const connection_record* connection;
};

struct connection_record;

struct bag_rdr::view
{
    view(const bag_rdr& rdr);
    void set_topics(array_view<const std::string> topics);
    void set_topics(array_view<const char*> topics);
    void set_topics(std::initializer_list<const char*> topics);
    void set_topics(array_view<string_view> topics);

    // C++11 ref-qualifiers for member functions
    // this prevents range-based for from not storing the result because it is of reference type
    view& with_topics(array_view<const std::string> topics) &  { set_topics(topics); return *this; }
    view  with_topics(array_view<const std::string> topics) && { set_topics(topics); return *this; }
    view& with_topics(array_view<const char*> topics) &  { set_topics(topics); return *this; }
    view  with_topics(array_view<const char*> topics) && { set_topics(topics); return *this; }
    view& with_topics(array_view<string_view> topics) &  { set_topics(topics); return *this; }
    view  with_topics(array_view<string_view> topics) && { set_topics(topics); return *this; }
    view& with_topics(std::initializer_list<const char*> topics) &  { set_topics(topics); return *this; }
    view  with_topics(std::initializer_list<const char*> topics) && { set_topics(topics); return *this; }
    view& with_start_time(timestamp start_time) &  { m_start_time = start_time; return *this; }
    view  with_start_time(timestamp start_time) && { m_start_time = start_time; return *this; }
    view& with_end_time(timestamp end_time) &  { m_end_time = end_time; return *this; }
    view  with_end_time(timestamp end_time) && { m_end_time = end_time; return *this; }
    view& with_time_range(timestamp start_time, timestamp end_time) &  { m_start_time = start_time; m_end_time = end_time; return *this; }
    view  with_time_range(timestamp start_time, timestamp end_time) && { m_start_time = start_time; m_end_time = end_time; return *this; }
    view& with_time_range_and_topics(timestamp start_time, timestamp end_time, array_view<const std::string> topics) &
        { m_start_time = start_time; m_end_time = end_time; set_topics(topics); return *this; }
    view  with_time_range_and_topics(timestamp start_time, timestamp end_time, array_view<const std::string> topics) &&
        { m_start_time = start_time; m_end_time = end_time; set_topics(topics); return *this; }

    using message = bag_rdr::message;

    struct iterator
    {
        const bag_rdr::view& v;
        struct pos_ref { int32_t block; int32_t record; bool operator==(const pos_ref& other) const {return block == other.block && record == other.record; } };
        std::vector<pos_ref> connection_positions;
        std::vector<int32_t> connection_order;

        struct constructor_start_tag {};
        iterator(const bag_rdr::view& v) : v(v) {};
        iterator(const bag_rdr::view& v, constructor_start_tag);
        iterator& operator=(const iterator&& other)
        {
            connection_positions = std::move(other.connection_positions);
            connection_order = std::move(other.connection_order);
            return *this;
        }
        iterator(const iterator& other) : v(other.v), connection_positions{other.connection_positions}, connection_order{other.connection_order} {}

        bool operator==(const iterator& other) const {
            return connection_positions == other.connection_positions;
        }
        bool operator!=(const iterator& other) const {
            return !(*this == other);
        }

        message operator*() const;

        iterator& operator++();
    };

    iterator begin();
    iterator end();

    std::vector<string_view> present_topics();
    bool has_topic(string_view topic);
    struct connection_data
    {
        string_view topic;
        string_view datatype;
        string_view md5sum;
        string_view msg_def;
        string_view callerid;
        bool latching;
    };
    void for_each_connection(const std::function<void (const connection_data& data)>& fn);

    void ensure_indices();

    // detail
    const bag_rdr& rdr;
    common::optional<std::vector<connection_record*>> m_connections;
    timestamp m_start_time, m_end_time;
};

#endif // BAG_RDR_HPP
