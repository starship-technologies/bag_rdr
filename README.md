bag_rdr: a zero-copy ROS bag parser library
-------------------------------------------------

### What is it?

An alternative to `librosbag` for reading (ROS)[http://www.ros.org/]
bag files. This is an independent implementation of reading the bag
file format only, it relies on the existing generated C++ message
parsing code for message content.

It is designed primarily to be fast; only allocating for decompression
buffers for compressed bags, and small vectors of indices for topic
selection and iteration.

Note that this has not been designed or validated for use against
adversarial input; use only bags from trusted sources.

### Dependencies

Requires a C++11 conformant compiler and STL implementation, and
pulls in [starship-technologies/common_cxx](https://github.com/starship-technologies/common_cxx)
as a git submodule.

Is packaged as a ROS catkin module depending on only the roscpp
serialization code, as well as bz2 and roslz4 for compressed bag support.

   `$ git clone https://github.com/starship-technologies/bag_rdr --recurse-submodules`

### Example

```cpp
bag_rdr bag{bag_filename};
for (bag_rdr::message msg : bag.get_view().with_topics({"/front_camera/camera_info", "/front_camera/image"})) {
    sensor_msgs::CameraInfo info;
    sensor_msgs::Image image;
    if (msg.to(info))
        use_info(msg.stamp, info);
    else if (msg.to(image))
        use_image(msg.stamp, image);
    else
        message_format_problem(msg.stamp, msg.topic(), msg.md5);
}
```

### Benchmark

#### LZ4 Compressed
```
--------------------------------------------------------
Benchmark                 Time           CPU Iterations
--------------------------------------------------------
benchmark_rosbag   64711665 ns   64535258 ns         11   230.596MB/s
benchmark_rdr      39551535 ns   39414273 ns         18   377.567MB/s
```

#### Uncompressed
```
--------------------------------------------------------
Benchmark                 Time           CPU Iterations
--------------------------------------------------------
benchmark_rosbag   45845031 ns   45762721 ns         14   538.379MB/s
benchmark_rdr      11907283 ns   11874861 ns         56   2.02615GB/s
```

These benchmarks run against a Starship production bag using a production topic subset,
bags are 14MB LZ4 compressed, or 24MB uncompressed.

### TODO

* Provide a version with no ROS dependencies (trivial: requires simple replacement of roslz4 with liblz4)
* Support non-linux platforms
* Support big-endian
* Decompress blocks ahead of user iteration in background thread

