project('bag_rdr', 'cpp', default_options: ['cpp_std=c++14'], version: '0.2.0')
add_project_arguments(['-Wno-maybe-uninitialized'], language : 'cpp')

deps = []
deps += dependency('liblz4')

if not get_option('common_cxx_fetch')
  common_cxx = declare_dependency(include_directories : include_directories('deps/common_cxx'))
  deps += common_cxx
else
  common_cxx = dependency('common_cxx')
  deps += common_cxx
endif

includes = []

extra_args = ['-DBAG_RDR_NO_ROS=1', '-DBAG_RDR_USE_SYSTEM_LZ4=1']
extra_args += get_option('extra_opt_flags')
if get_option('disable_bz2')
  extra_args += '-DDISABLE_BZ2'
else
  deps += declare_dependency(link_with : library('bz2'))
endif

sources = ['bag_rdr.cpp']
lib = static_library('bag_rdr', sources, cpp_args: extra_args, dependencies: deps, install: true)
install_headers('bag_rdr.hpp')
if not get_option('common_cxx_fetch')
  install_subdir('deps/common_cxx', install_dir : 'include')
endif

pkg = import('pkgconfig')
libs = deps
h = includes
pkg.generate(lib,
             libraries: deps,
             version : '0.1',
             name : 'bag_rdr',
             filebase : 'bag_rdr',
             description : 'A fast ROS bag reading library.',
             subdirs: ['.', 'common_cxx'],
             extra_cflags : extra_args)

# For wrap/subproject use
bag_rdr_dep = declare_dependency(link_with: [lib], include_directories: ['.'], dependencies: deps, compile_args: extra_args)
meson.override_dependency('bag_rdr', bag_rdr_dep)
