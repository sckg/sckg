# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 2.8

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The program to use to edit the cache.
CMAKE_EDIT_COMMAND = /usr/bin/ccmake

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/content-0.1.47

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/content-0.1.47/build

# Utility rule file for generate-ssg-wrlinux8-cpe-dictionary.xml.

# Include the progress variables for this target.
include wrlinux8/CMakeFiles/generate-ssg-wrlinux8-cpe-dictionary.xml.dir/progress.make

wrlinux8/CMakeFiles/generate-ssg-wrlinux8-cpe-dictionary.xml: ssg-wrlinux8-cpe-dictionary.xml
wrlinux8/CMakeFiles/generate-ssg-wrlinux8-cpe-dictionary.xml: ssg-wrlinux8-cpe-oval.xml

ssg-wrlinux8-cpe-dictionary.xml: wrlinux8/oval-unlinked.xml
ssg-wrlinux8-cpe-dictionary.xml: ../wrlinux8/cpe/wrlinux8-cpe-dictionary.xml
ssg-wrlinux8-cpe-dictionary.xml: ../build-scripts/cpe_generate.py
	$(CMAKE_COMMAND) -E cmake_progress_report /root/content-0.1.47/build/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold "[wrlinux8-content] generating ssg-wrlinux8-cpe-dictionary.xml, ssg-wrlinux8-cpe-oval.xml"
	cd /root/content-0.1.47/build/wrlinux8 && env PYTHONPATH=/root/content-0.1.47 /bin/python /root/content-0.1.47/build-scripts/cpe_generate.py wrlinux8 ssg /root/content-0.1.47/build /root/content-0.1.47/build/wrlinux8/oval-unlinked.xml /root/content-0.1.47/wrlinux8/cpe/wrlinux8-cpe-dictionary.xml
	cd /root/content-0.1.47/build/wrlinux8 && /bin/xmllint --nsclean --format --output /root/content-0.1.47/build/ssg-wrlinux8-cpe-dictionary.xml /root/content-0.1.47/build/ssg-wrlinux8-cpe-dictionary.xml
	cd /root/content-0.1.47/build/wrlinux8 && /bin/xmllint --nsclean --format --output /root/content-0.1.47/build/ssg-wrlinux8-cpe-oval.xml /root/content-0.1.47/build/ssg-wrlinux8-cpe-oval.xml

ssg-wrlinux8-cpe-oval.xml: ssg-wrlinux8-cpe-dictionary.xml

wrlinux8/oval-unlinked.xml: ../build-scripts/combine_ovals.py
	$(CMAKE_COMMAND) -E cmake_progress_report /root/content-0.1.47/build/CMakeFiles $(CMAKE_PROGRESS_2)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold "[wrlinux8-content] generating oval-unlinked.xml"
	cd /root/content-0.1.47/build/wrlinux8 && env PYTHONPATH=/root/content-0.1.47 /bin/python /root/content-0.1.47/build-scripts/combine_ovals.py --build-config-yaml /root/content-0.1.47/build/build_config.yml --product-yaml /root/content-0.1.47/wrlinux8/product.yml --output /root/content-0.1.47/build/wrlinux8/oval-unlinked.xml /root/content-0.1.47/build/wrlinux8/checks/shared/oval /root/content-0.1.47/shared/checks/oval /root/content-0.1.47/build/wrlinux8/checks/oval /root/content-0.1.47/wrlinux8/checks/oval
	cd /root/content-0.1.47/build/wrlinux8 && /bin/xmllint --format --output /root/content-0.1.47/build/wrlinux8/oval-unlinked.xml /root/content-0.1.47/build/wrlinux8/oval-unlinked.xml

generate-ssg-wrlinux8-cpe-dictionary.xml: wrlinux8/CMakeFiles/generate-ssg-wrlinux8-cpe-dictionary.xml
generate-ssg-wrlinux8-cpe-dictionary.xml: ssg-wrlinux8-cpe-dictionary.xml
generate-ssg-wrlinux8-cpe-dictionary.xml: ssg-wrlinux8-cpe-oval.xml
generate-ssg-wrlinux8-cpe-dictionary.xml: wrlinux8/oval-unlinked.xml
generate-ssg-wrlinux8-cpe-dictionary.xml: wrlinux8/CMakeFiles/generate-ssg-wrlinux8-cpe-dictionary.xml.dir/build.make
.PHONY : generate-ssg-wrlinux8-cpe-dictionary.xml

# Rule to build all files generated by this target.
wrlinux8/CMakeFiles/generate-ssg-wrlinux8-cpe-dictionary.xml.dir/build: generate-ssg-wrlinux8-cpe-dictionary.xml
.PHONY : wrlinux8/CMakeFiles/generate-ssg-wrlinux8-cpe-dictionary.xml.dir/build

wrlinux8/CMakeFiles/generate-ssg-wrlinux8-cpe-dictionary.xml.dir/clean:
	cd /root/content-0.1.47/build/wrlinux8 && $(CMAKE_COMMAND) -P CMakeFiles/generate-ssg-wrlinux8-cpe-dictionary.xml.dir/cmake_clean.cmake
.PHONY : wrlinux8/CMakeFiles/generate-ssg-wrlinux8-cpe-dictionary.xml.dir/clean

wrlinux8/CMakeFiles/generate-ssg-wrlinux8-cpe-dictionary.xml.dir/depend:
	cd /root/content-0.1.47/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/content-0.1.47 /root/content-0.1.47/wrlinux8 /root/content-0.1.47/build /root/content-0.1.47/build/wrlinux8 /root/content-0.1.47/build/wrlinux8/CMakeFiles/generate-ssg-wrlinux8-cpe-dictionary.xml.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : wrlinux8/CMakeFiles/generate-ssg-wrlinux8-cpe-dictionary.xml.dir/depend
