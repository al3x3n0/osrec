cmake_minimum_required(VERSION 3.20)
project(osrec C)
option(OSREC_BUILD_LLVM_PLANNER "Build the optional LLVM 22 analysis plugin" OFF)
option(OSREC_BUILD_EL0_ANALYZER "Build the EL0 analyzer/extractor using LLVM 16 or 22" ${OSREC_BUILD_LLVM_PLANNER})
option(OSREC_BUILD_EL0_EXPORT_TESTS "Enable EL0 symbolic export checks with a matching KLEE toolchain" OFF)
option(OSREC_BUILD_LITEOS_KLEE_SCENARIO "Enable the pinned LiteOS-A KLEE, trace analysis and standalone export tests" OFF)
option(OSREC_BUILD_QEMU_DEMO "Enable the ARM user/SVC capture and native replay demo test" OFF)
option(OSREC_BUILD_LIVE_LITEOS_QEMU_DEMO "Enable actual LiteOS-A boot/capture/replay regression (requires prepared dependencies)" OFF)
option(OSREC_BUILD_FREESTANDING_IMAGE_TESTS "Enable freestanding ARMv7/AArch64 image regressions (requires pinned source, LLVM and QEMU)" OFF)
option(OSREC_BUILD_KERNEL_BINARY_REPLAY "Build the QEMU footprint plugin and test capture/replay of live SVC boundaries with the kernel's own machine code (requires QEMU plugin headers, glib and the state checkpoint under build/)" OFF)
option(OSREC_BUILD_KLEE_STATE_BATCH "Rerun KLEE state discovery and validation for the captured Linux boundaries (requires KLEE, QEMU and the captured inputs under build/)" OFF)
set(OSREC_KLEE_STATE_BATCH_TIERS "quick" CACHE STRING "Manifest tiers of the KLEE state batch, one test each (quick, long)")
set(OSREC_LITEOS_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/build/kernel_liteos_a" CACHE PATH "Pinned LiteOS-A checkout")
set(OSREC_KLEE_LLVM_BIN "/opt/homebrew/opt/llvm@16/bin" CACHE PATH "LLVM tools matching the KLEE build")
set(OSREC_KLEE_INCLUDE "/opt/homebrew/opt/klee/include" CACHE PATH "Directory containing klee/klee.h")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_library(osrec STATIC runtime/recorder.c runtime/context.c runtime/checkpoint.c runtime/io_capture.c runtime/entry_snapshot.c runtime/entry_capture.c runtime/object_lifetime.c)
target_include_directories(osrec PUBLIC include)
target_compile_options(osrec PRIVATE -Wall -Wextra -Werror)
# Refresh the fingerprint whenever the replayable source changes.
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS examples/region.h)
file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/examples/region.h" REGION_SHA256)
add_executable(record_demo examples/record_demo.c)
target_link_libraries(record_demo PRIVATE osrec)
target_compile_definitions(record_demo PRIVATE OSREC_BUILD_ID="${REGION_SHA256}")
target_compile_options(record_demo PRIVATE -Wall -Wextra -Werror)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS examples/task_region.h)
file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/examples/task_region.h" TASK_SHA256)
add_executable(record_task_demo examples/record_task_demo.c)
target_link_libraries(record_task_demo PRIVATE osrec)
target_compile_definitions(record_task_demo PRIVATE OSREC_TASK_BUILD_ID="${TASK_SHA256}")
target_compile_options(record_task_demo PRIVATE -Wall -Wextra -Werror)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS examples/object_region.h)
file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/examples/object_region.h" OBJECT_SHA256)
add_executable(record_object_demo examples/record_object_demo.c)
target_link_libraries(record_object_demo PRIVATE osrec)
target_compile_definitions(record_object_demo PRIVATE OSREC_OBJECT_BUILD_ID="${OBJECT_SHA256}")
target_compile_options(record_object_demo PRIVATE -Wall -Wextra -Werror)
include(CTest)
if(OSREC_BUILD_LLVM_PLANNER OR OSREC_BUILD_EL0_ANALYZER)
  enable_language(CXX)
  find_package(LLVM REQUIRED CONFIG)
  if(OSREC_BUILD_LLVM_PLANNER AND NOT LLVM_VERSION_MAJOR EQUAL 22)
    message(FATAL_ERROR "The planner is currently validated with LLVM 22 only")
  endif()
  separate_arguments(OSREC_LLVM_DEFINITIONS NATIVE_COMMAND "${LLVM_DEFINITIONS}")
  if(OSREC_BUILD_LLVM_PLANNER)
    add_library(osrec_plan MODULE compiler/Planner.cpp)
    set_target_properties(osrec_plan PROPERTIES PREFIX "" CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
    target_include_directories(osrec_plan SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
    target_compile_options(osrec_plan PRIVATE ${OSREC_LLVM_DEFINITIONS} -Wall -Wextra -Werror)
    if(NOT LLVM_ENABLE_RTTI)
      target_compile_options(osrec_plan PRIVATE -fno-rtti)
    endif()
    target_link_libraries(osrec_plan PRIVATE LLVM)
  endif()
  if(OSREC_BUILD_EL0_ANALYZER)
    if(NOT LLVM_VERSION_MAJOR EQUAL 16 AND NOT LLVM_VERSION_MAJOR EQUAL 22)
      message(FATAL_ERROR "EL0 analysis is currently validated with LLVM 16 and 22 only")
    endif()
    add_library(osrec_el0 MODULE compiler/El0Analyzer.cpp)
    set_target_properties(osrec_el0 PROPERTIES PREFIX "" CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
    target_include_directories(osrec_el0 SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
    target_compile_options(osrec_el0 PRIVATE ${OSREC_LLVM_DEFINITIONS} -Wall -Wextra -Werror)
    if(NOT LLVM_ENABLE_RTTI)
      target_compile_options(osrec_el0 PRIVATE -fno-rtti)
    endif()
    target_link_libraries(osrec_el0 PRIVATE LLVM)
  endif()
endif()
if(BUILD_TESTING)
  add_executable(recorder_tests tests/recorder_tests.c)
  target_link_libraries(recorder_tests PRIVATE osrec)
  target_compile_options(recorder_tests PRIVATE -Wall -Wextra -Werror)
  add_test(NAME recorder COMMAND recorder_tests)
  add_executable(io_capture_tests tests/io_capture_tests.c)
  target_link_libraries(io_capture_tests PRIVATE osrec)
  target_compile_options(io_capture_tests PRIVATE -Wall -Wextra -Werror)
  add_test(NAME read_capture_hook COMMAND io_capture_tests)
  add_executable(context_tests tests/context_tests.c)
  target_link_libraries(context_tests PRIVATE osrec)
  target_compile_options(context_tests PRIVATE -Wall -Wextra -Werror)
  add_test(NAME contexts COMMAND context_tests)
  add_executable(checkpoint_tests tests/checkpoint_tests.c)
  target_link_libraries(checkpoint_tests PRIVATE osrec)
  target_compile_options(checkpoint_tests PRIVATE -Wall -Wextra -Werror)
  add_test(NAME object_references COMMAND checkpoint_tests)
  add_executable(entry_snapshot_tests tests/entry_snapshot_tests.c)
  target_link_libraries(entry_snapshot_tests PRIVATE osrec)
  target_compile_options(entry_snapshot_tests PRIVATE -Wall -Wextra -Werror)
  add_test(NAME entry_snapshot_objects COMMAND entry_snapshot_tests)
  add_executable(object_lifetime_tests tests/object_lifetime_tests.c)
  target_link_libraries(object_lifetime_tests PRIVATE osrec)
  target_compile_options(object_lifetime_tests PRIVATE -Wall -Wextra -Werror)
  add_test(NAME object_lifetimes COMMAND object_lifetime_tests)
  find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
  foreach(check IN ITEMS el0_application el0_image_audit el0_model el0_flat el0_hardware el0_lowered_branch el0_memory_finish el0_observe kernel_data_symbols kernel_excerpts)
    add_test(NAME ${check} COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_${check}.py)
    set_tests_properties(${check} PROPERTIES TIMEOUT 120)
  endforeach()
  find_program(OSREC_ENTRY_CLANG NAMES clang HINTS "${OSREC_KLEE_LLVM_BIN}")
  if(OSREC_ENTRY_CLANG)
    add_test(NAME entry_state_analysis COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state.py ${OSREC_ENTRY_CLANG})
    set_tests_properties(entry_state_analysis PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_reconstruction COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_reconstruct_entry_state.py ${OSREC_ENTRY_CLANG})
    set_tests_properties(entry_state_reconstruction PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_program COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_program.py ${OSREC_ENTRY_CLANG})
    set_tests_properties(entry_state_program PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_global_arrays COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_global_arrays.py ${OSREC_ENTRY_CLANG})
    set_tests_properties(entry_state_global_arrays PROPERTIES TIMEOUT 120)
    add_test(NAME kernel_state_discovery COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_kernel_state_discovery.py ${OSREC_ENTRY_CLANG})
    set_tests_properties(kernel_state_discovery PROPERTIES TIMEOUT 120)
    add_test(NAME call_closure_coverage COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_call_closure_coverage.py ${OSREC_ENTRY_CLANG})
    set_tests_properties(call_closure_coverage PROPERTIES TIMEOUT 120)
    add_test(NAME mixed_call_closure COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_mixed_call_closure.py ${OSREC_ENTRY_CLANG})
    set_tests_properties(mixed_call_closure PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_dominance COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_dominance.py ${OSREC_ENTRY_CLANG})
    set_tests_properties(entry_state_dominance PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_effects COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_effects.py ${OSREC_ENTRY_CLANG})
    set_tests_properties(entry_state_effects PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_continuity COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_continuity.py ${OSREC_ENTRY_CLANG})
    set_tests_properties(entry_state_continuity PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_lifetimes COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_lifetimes.py)
  endif()
  if(OSREC_BUILD_FREESTANDING_IMAGE_TESTS)
    find_program(OSREC_IMAGE_QEMU_AARCH64 NAMES qemu-system-aarch64 REQUIRED)
    add_test(NAME async_task COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_async_task.py
      $<TARGET_FILE:record_task_demo> ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(async_task PROPERTIES TIMEOUT 180)
    add_test(NAME linux_irq COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_irq.py ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(linux_irq PROPERTIES TIMEOUT 300)
    add_test(NAME image_memory COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_image_memory.py --llvm-bin ${OSREC_KLEE_LLVM_BIN})
    set_tests_properties(image_memory PROPERTIES TIMEOUT 60)
    add_test(NAME freestanding_aarch64 COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_freestanding_aarch64.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(freestanding_aarch64 PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_ranges COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_ranges.py
      ${OSREC_KLEE_LLVM_BIN}/clang ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_ranges PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_constant_indices COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_constant_indices.py
      ${OSREC_KLEE_LLVM_BIN}/clang ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_constant_indices PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_automatic_arrays COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_automatic_arrays.py
      ${OSREC_KLEE_LLVM_BIN}/clang ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_automatic_arrays PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_loops COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_loops.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_loops PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_multidimensional COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_multidimensional.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_multidimensional PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_selections COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_selections.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_selections PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_local_effects COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_local_effects.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_local_effects PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_program_slicing COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_program_slicing.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_program_slicing PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_alias_limits COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_alias_limits.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_alias_limits PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_alias_syntax COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_alias_syntax.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_alias_syntax PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_automatic_records COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_automatic_records.py
      ${CMAKE_C_COMPILER})
    set_tests_properties(entry_state_automatic_records PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_compound_literals COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_compound_literals.py
      ${CMAKE_C_COMPILER})
    set_tests_properties(entry_state_compound_literals PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_constant_globals COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_constant_globals.py
      ${CMAKE_C_COMPILER})
    set_tests_properties(entry_state_constant_globals PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_constant_arrays COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_constant_arrays.py
      ${CMAKE_C_COMPILER})
    set_tests_properties(entry_state_constant_arrays PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_gnu_conditional COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_gnu_conditional.py
      ${CMAKE_C_COMPILER})
    set_tests_properties(entry_state_gnu_conditional PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_integer_builtins COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_integer_builtins.py
      ${CMAKE_C_COMPILER})
    set_tests_properties(entry_state_integer_builtins PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_constant_records COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_constant_records.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_constant_records PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_wide_indices COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_wide_indices.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_wide_indices PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_local_indices COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_local_indices.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_local_indices PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_pointer_returns COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_pointer_returns.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_pointer_returns PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_pointer_initialization COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_pointer_initialization.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_pointer_initialization PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_bounded_pointers COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_bounded_pointers.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_bounded_pointers PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_path_facts COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_path_facts.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_path_facts PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_kernel_idioms COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_kernel_idioms.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_kernel_idioms PROPERTIES TIMEOUT 120)
    add_test(NAME klee_state_discovery_queries COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_klee_state_discovery.py)
    set_tests_properties(klee_state_discovery_queries PROPERTIES TIMEOUT 60)
    add_test(NAME klee_state_validation_inputs COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_klee_state_validation.py)
    set_tests_properties(klee_state_validation_inputs PROPERTIES TIMEOUT 60)
    add_test(NAME klee_state_batch_manifest COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_klee_state_batch.py)
    set_tests_properties(klee_state_batch_manifest PROPERTIES TIMEOUT 60)
    add_test(NAME entry_state_pointer_arithmetic COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_pointer_arithmetic.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_pointer_arithmetic PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_incomplete_arrays COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_incomplete_arrays.py
      ${CMAKE_C_COMPILER})
    set_tests_properties(entry_state_incomplete_arrays PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_guarded_loops COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_guarded_loops.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_guarded_loops PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_affine_indices COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_affine_indices.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_affine_indices PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_constant_bounds COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_constant_bounds.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_constant_bounds PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_enum_operators COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_enum_operators.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_enum_operators PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_constant_expressions COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_constant_expressions.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_constant_expressions PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_comparisons COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_comparisons.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_comparisons PROPERTIES TIMEOUT 180)
    add_test(NAME discovered_call_closure COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_discovered_call_closure.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(discovered_call_closure PROPERTIES TIMEOUT 180)
    add_test(NAME discovered_constant_data COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_discovered_constant_data.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(discovered_constant_data PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_pointer_differences COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_pointer_differences.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_pointer_differences PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_pointer_comparisons COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_pointer_comparisons.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_pointer_comparisons PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_pointer_updates COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_pointer_updates.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_pointer_updates PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_consumed_pointer_updates COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_consumed_pointer_updates.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_consumed_pointer_updates PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_pointer_update_stores COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_pointer_update_stores.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_pointer_update_stores PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_cursor_loops COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_cursor_loops.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_cursor_loops PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_strided_cursor_loops COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_strided_cursor_loops.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_strided_cursor_loops PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_paired_cursor_loops COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_paired_cursor_loops.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_paired_cursor_loops PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_bounded_count_cursor_loops COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_bounded_count_cursor_loops.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_bounded_count_cursor_loops PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_constant_cursor_loops COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_constant_cursor_loops.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_constant_cursor_loops PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_local_volatile COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_local_volatile.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_local_volatile PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_assigned_volatile COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_assigned_volatile.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_assigned_volatile PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_scalar_addresses COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_scalar_addresses.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_scalar_addresses PROPERTIES TIMEOUT 180)
    add_test(NAME entry_state_self_recursion COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_self_recursion.py
      ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(entry_state_self_recursion PROPERTIES TIMEOUT 180)
    add_test(NAME numeric_entry_adapter COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_numeric_entry_adapter.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(numeric_entry_adapter PROPERTIES TIMEOUT 240)
    add_test(NAME entry_state_arguments COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_arguments.py
      ${OSREC_KLEE_LLVM_BIN}/clang ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_arguments PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_argument_dominance COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_argument_dominance.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_argument_dominance PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_sequence_dominance COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_sequence_dominance.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_sequence_dominance PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_conditional_dominance COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_conditional_dominance.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_conditional_dominance PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_write_preservation COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_write_preservation.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_write_preservation PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_nested_preservation COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_nested_preservation.py
      ${OSREC_KLEE_LLVM_BIN}/clang ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_nested_preservation PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_null_guard COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_null_guard.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_null_guard PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_export COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_export.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_export PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_capture COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_capture.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_capture PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_dispatch COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_dispatch.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_dispatch PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_long_session COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_long_session.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_long_session PROPERTIES TIMEOUT 180)
    add_test(NAME const_entry_state COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_const_entry_state.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(const_entry_state PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_pointer_effects COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_pointer_effects.py
      ${OSREC_KLEE_LLVM_BIN}/clang ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_pointer_effects PROPERTIES TIMEOUT 120)
    add_test(NAME entry_state_nested_effects COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_entry_state_nested_effects.py
      ${OSREC_KLEE_LLVM_BIN}/clang ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(entry_state_nested_effects PROPERTIES TIMEOUT 120)
    add_test(NAME freestanding_task COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_freestanding_task.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(freestanding_task PROPERTIES TIMEOUT 120)
    add_test(NAME freestanding_credentials COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_freestanding_credentials.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(freestanding_credentials PROPERTIES TIMEOUT 120)
    add_test(NAME freestanding_getpriority COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_freestanding_getpriority.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(freestanding_getpriority PROPERTIES TIMEOUT 120)
    add_test(NAME freestanding_clocks COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_freestanding_clocks.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(freestanding_clocks PROPERTIES TIMEOUT 120)
    add_test(NAME freestanding_rlimit COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_freestanding_rlimit.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(freestanding_rlimit PROPERTIES TIMEOUT 120)
    add_test(NAME freestanding_uname COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_freestanding_uname.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(freestanding_uname PROPERTIES TIMEOUT 120)
    add_test(NAME freestanding_close COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_freestanding_close.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(freestanding_close PROPERTIES TIMEOUT 120)
    add_test(NAME freestanding_dup COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_freestanding_dup.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(freestanding_dup PROPERTIES TIMEOUT 120)
    add_test(NAME freestanding_files COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_freestanding_files.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(freestanding_files PROPERTIES TIMEOUT 180)
    add_test(NAME freestanding_callable_slices COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_callable_slices.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(freestanding_callable_slices PROPERTIES TIMEOUT 180)
    add_test(NAME freestanding_application_frames COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_application_frames.py)
    set_tests_properties(freestanding_application_frames PROPERTIES TIMEOUT 180)
    add_test(NAME freestanding_cpu_gateway COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cpu_gateway.py)
    set_tests_properties(freestanding_cpu_gateway PROPERTIES TIMEOUT 180)
    add_test(NAME freestanding_application_import COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_application_import.py)
    set_tests_properties(freestanding_application_import PROPERTIES TIMEOUT 240)
    add_test(NAME freestanding_application_windows COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_application_windows.py)
    set_tests_properties(freestanding_application_windows PROPERTIES TIMEOUT 240)
    add_test(NAME freestanding_application_checkpoints COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_application_checkpoints.py)
    set_tests_properties(freestanding_application_checkpoints PROPERTIES TIMEOUT 240)
    add_test(NAME freestanding_application_checkpoint_chain COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_application_checkpoint_chain.py)
    set_tests_properties(freestanding_application_checkpoint_chain PROPERTIES TIMEOUT 240)
    add_test(NAME qemu_vm_checkpoint_contract COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_qemu_vm_checkpoint.py)
    set_tests_properties(qemu_vm_checkpoint_contract PROPERTIES TIMEOUT 30)
    add_test(NAME svc_boundary_reduced_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_svc_boundary.py)
    set_tests_properties(svc_boundary_reduced_replay PROPERTIES TIMEOUT 240)
    add_test(NAME kernel_type_sources COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_kernel_types.py)
    set_tests_properties(kernel_type_sources PROPERTIES TIMEOUT 240)
    add_test(NAME joint_checkpoint_feedback COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_joint_checkpoint_feedback.py)
    set_tests_properties(joint_checkpoint_feedback PROPERTIES TIMEOUT 240)
    add_test(NAME discovered_joint_execution COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_discovered_joint_execution.py)
    set_tests_properties(discovered_joint_execution PROPERTIES TIMEOUT 240)
    add_test(NAME freestanding_external_slice_port COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_external_slice_port.py)
    set_tests_properties(freestanding_external_slice_port PROPERTIES TIMEOUT 240)
    add_test(NAME freestanding_context_graph_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_context_graph_checkpoint.py)
    set_tests_properties(freestanding_context_graph_checkpoint PROPERTIES TIMEOUT 240)
    add_test(NAME freestanding_context_buffer_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_context_buffer_checkpoint.py)
    set_tests_properties(freestanding_context_buffer_checkpoint PROPERTIES TIMEOUT 240)
    add_test(NAME freestanding_mixed_declaration_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_mixed_declaration_checkpoint.py)
    set_tests_properties(freestanding_mixed_declaration_checkpoint PROPERTIES TIMEOUT 240)
    add_test(NAME freestanding_source_bytes_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_source_bytes_checkpoint.py)
    set_tests_properties(freestanding_source_bytes_checkpoint PROPERTIES TIMEOUT 240)
    add_test(NAME freestanding_local_enum_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_local_enum_checkpoint.py)
    set_tests_properties(freestanding_local_enum_checkpoint PROPERTIES TIMEOUT 240)
    add_test(NAME freestanding_linux_aarch64_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_checkpoint PROPERTIES TIMEOUT 300)
    add_test(NAME freestanding_linux_aarch64_credentials_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_credentials_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_credentials_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_fsgid_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_fsgid_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_fsgid_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_group_setters_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_group_setters_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_group_setters_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_getgroups_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_getgroups_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_getgroups_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_setgroups_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_setgroups_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_setgroups_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_setgroups_denied_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_setgroups_denied_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_setgroups_denied_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_capabilities_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_capabilities_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_capabilities_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_capget_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_capget_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_capget_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_prctl_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_prctl_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_prctl_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_fsuid_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_fsuid_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_fsuid_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_setresuid_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_setresuid_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_setresuid_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_uid_setters_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_uid_setters_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_uid_setters_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_credential_setters_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_credential_setters_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_credential_setters_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_fd_dup_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_fd_dup_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_fd_dup_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_file_io_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_file_io_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_file_io_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_file_positioned_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_file_positioned_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_file_positioned_checkpoint PROPERTIES TIMEOUT 900)
    add_test(NAME freestanding_linux_aarch64_fd_control_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_fd_control_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_fd_control_checkpoint PROPERTIES TIMEOUT 1200)
    add_test(NAME freestanding_linux_aarch64_close_range_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_close_range_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_close_range_checkpoint PROPERTIES TIMEOUT 1200)
    add_test(NAME freestanding_linux_aarch64_fstat_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_fstat_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_fstat_checkpoint PROPERTIES TIMEOUT 1200)
    add_test(NAME freestanding_linux_aarch64_fchmod_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_fchmod_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_fchmod_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME freestanding_linux_aarch64_fchown_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_fchown_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_fchown_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME freestanding_linux_aarch64_fchown_capable_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_fchown_capable_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_fchown_capable_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME freestanding_linux_aarch64_file_capabilities_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_file_capabilities_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_file_capabilities_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME freestanding_linux_aarch64_file_fsgid_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_file_fsgid_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_file_fsgid_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME freestanding_linux_aarch64_file_fsuid_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_file_fsuid_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_file_fsuid_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME freestanding_linux_aarch64_file_groups_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_file_groups_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_file_groups_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME freestanding_linux_aarch64_file_group_setters_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_file_group_setters_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_file_group_setters_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME freestanding_linux_aarch64_file_status_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_file_status_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_file_status_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME freestanding_linux_aarch64_file_capget_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_file_capget_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_file_capget_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME freestanding_linux_aarch64_file_prctl_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_file_prctl_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_file_prctl_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME freestanding_linux_aarch64_file_credentials_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_file_credentials_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_file_credentials_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME freestanding_linux_aarch64_file_rlimit_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_file_rlimit_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_file_rlimit_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME freestanding_linux_aarch64_file_limits_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_file_limits_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_file_limits_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME freestanding_linux_aarch64_file_setrlimit_checkpoint COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_file_setrlimit_checkpoint.py)
    set_tests_properties(freestanding_linux_aarch64_file_setrlimit_checkpoint PROPERTIES TIMEOUT 2400)
    add_test(NAME linux_aarch64_preflight COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_linux_aarch64_preflight.py)
    set_tests_properties(linux_aarch64_preflight PROPERTIES TIMEOUT 180)
    add_test(NAME freestanding_elf_checkpoint_chain COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_elf_checkpoint_chain.py)
    set_tests_properties(freestanding_elf_checkpoint_chain PROPERTIES TIMEOUT 240)
    find_program(OSREC_IMAGE_QEMU_ARM NAMES qemu-system-arm REQUIRED)
    add_test(NAME freestanding_umask COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_freestanding_umask.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_ARM})
    set_tests_properties(freestanding_umask PROPERTIES TIMEOUT 120)
    add_test(NAME freestanding_identity COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_freestanding_identity.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_ARM})
    set_tests_properties(freestanding_identity PROPERTIES TIMEOUT 120)
    add_test(NAME freestanding_scalar COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_freestanding_scalar.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_ARM})
    set_tests_properties(freestanding_scalar PROPERTIES TIMEOUT 120)
    add_test(NAME freestanding_read COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_freestanding_read.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_ARM})
    set_tests_properties(freestanding_read PROPERTIES TIMEOUT 120)
  endif()
  if(OSREC_BUILD_LIVE_LITEOS_QEMU_DEMO)
    add_test(NAME live_wait_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_wait_replay.py ${OSREC_LITEOS_SOURCE} ${CMAKE_C_COMPILER})
    set_tests_properties(live_wait_replay PROPERTIES TIMEOUT 60)
    add_test(NAME live_clocks_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_clocks_replay.py)
    set_tests_properties(live_clocks_replay PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    add_test(NAME live_rlimit_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_rlimit_replay.py)
    set_tests_properties(live_rlimit_replay PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    add_test(NAME live_uname_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_uname_replay.py)
    set_tests_properties(live_uname_replay PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    add_test(NAME live_close_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_close_replay.py)
    set_tests_properties(live_close_replay PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    add_test(NAME live_dup_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_dup_replay.py)
    set_tests_properties(live_dup_replay PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    add_test(NAME live_files_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_files_replay.py)
    set_tests_properties(live_files_replay PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    add_test(NAME live_callable_slices COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_callable_slices.py)
    set_tests_properties(live_callable_slices PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    add_test(NAME live_liteos_qemu COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_liteos_qemu.py)
    set_tests_properties(live_liteos_qemu PROPERTIES TIMEOUT 360 RUN_SERIAL TRUE)
    add_test(NAME live_entry_state COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_entry_state.py)
    set_tests_properties(live_entry_state PROPERTIES TIMEOUT 900 RUN_SERIAL TRUE)
    find_program(OSREC_LIVE_ARGUMENT_QEMU_AARCH64 NAMES qemu-system-aarch64 REQUIRED)
    add_test(NAME live_argument_state COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_argument_state.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_LIVE_ARGUMENT_QEMU_AARCH64})
    set_tests_properties(live_argument_state PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    add_test(NAME live_const_argument_state COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_const_argument_state.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_LIVE_ARGUMENT_QEMU_AARCH64})
    set_tests_properties(live_const_argument_state PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    add_test(NAME live_argument_effects COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_argument_effects.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_LIVE_ARGUMENT_QEMU_AARCH64})
    set_tests_properties(live_argument_effects PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    add_test(NAME live_argument_session COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_argument_session.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_LIVE_ARGUMENT_QEMU_AARCH64})
    set_tests_properties(live_argument_session PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    add_test(NAME live_parent_argument COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_parent_argument.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_LIVE_ARGUMENT_QEMU_AARCH64})
    set_tests_properties(live_parent_argument PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    add_test(NAME live_shared_capture COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_shared_capture.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(live_shared_capture PROPERTIES TIMEOUT 360 RUN_SERIAL TRUE)
    add_test(NAME live_shared_mixed COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_shared_mixed.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(live_shared_mixed PROPERTIES TIMEOUT 360 RUN_SERIAL TRUE)
    add_test(NAME live_configured_capture COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_configured_capture.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(live_configured_capture PROPERTIES TIMEOUT 660 RUN_SERIAL TRUE)
    add_test(NAME live_generated_dispatch COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_generated_dispatch.py
      ${OSREC_KLEE_LLVM_BIN} ${OSREC_IMAGE_QEMU_AARCH64})
    set_tests_properties(live_generated_dispatch PROPERTIES TIMEOUT 600 RUN_SERIAL TRUE)
    add_test(NAME live_getgroups_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_getgroups_replay.py)
    set_tests_properties(live_getgroups_replay PROPERTIES TIMEOUT 1500 RUN_SERIAL TRUE)
    add_test(NAME live_getresuid_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_getresuid_replay.py)
    set_tests_properties(live_getresuid_replay PROPERTIES TIMEOUT 360 RUN_SERIAL TRUE)
    add_test(NAME live_getresgid_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_getresgid_replay.py)
    set_tests_properties(live_getresgid_replay PROPERTIES TIMEOUT 360 RUN_SERIAL TRUE)
    add_test(NAME credential_entry_state COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_credential_entry_state.py)
    add_test(NAME live_credential_output_geometry COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_credential_output_geometry.py)
    set_tests_properties(live_credential_output_geometry PROPERTIES TIMEOUT 900 RUN_SERIAL TRUE)
    add_test(NAME live_getscheduler_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_getscheduler_replay.py)
    set_tests_properties(live_getscheduler_replay PROPERTIES TIMEOUT 360 RUN_SERIAL TRUE)
    add_test(NAME live_getscheduler_task_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_getscheduler_task_replay.py)
    set_tests_properties(live_getscheduler_task_replay PROPERTIES TIMEOUT 360 RUN_SERIAL TRUE)
    add_test(NAME live_credential_ids COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_credential_ids.py)
    set_tests_properties(live_credential_ids PROPERTIES TIMEOUT 900 RUN_SERIAL TRUE)
    add_test(NAME live_identity_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_identity_replay.py)
    set_tests_properties(live_identity_replay PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE)
    add_test(NAME live_umask_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_live_umask_replay.py)
    set_tests_properties(live_umask_replay PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE)
  endif()
  if(OSREC_BUILD_QEMU_DEMO)
    find_program(OSREC_QEMU_ARM NAMES qemu-system-arm REQUIRED)
    find_program(OSREC_QEMU_CLANG NAMES clang PATHS ${OSREC_KLEE_LLVM_BIN} NO_DEFAULT_PATH REQUIRED)
    add_test(NAME qemu_sysread COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_qemu_sysread.py
      ${OSREC_LITEOS_SOURCE} ${OSREC_QEMU_CLANG} ${OSREC_QEMU_ARM} ${CMAKE_C_COMPILER})
    set_tests_properties(qemu_sysread PROPERTIES TIMEOUT 360)
  endif()
  add_test(NAME capsule COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_capsule.py
    $<TARGET_FILE:record_demo> ${CMAKE_C_COMPILER})
  add_test(NAME task_capsule COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_task_capsule.py
    $<TARGET_FILE:record_task_demo> ${CMAKE_C_COMPILER})
  add_test(NAME object_checkpoint COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_object_checkpoint.py
    $<TARGET_FILE:record_object_demo> ${CMAKE_C_COMPILER})
  if(OSREC_BUILD_LLVM_PLANNER OR OSREC_BUILD_EL0_ANALYZER)
    find_program(OSREC_OPT NAMES opt PATHS ${LLVM_TOOLS_BINARY_DIR} NO_DEFAULT_PATH REQUIRED)
  endif()
  if(OSREC_BUILD_LLVM_PLANNER)
    add_test(NAME planner COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_planner.py
      ${OSREC_OPT} $<TARGET_FILE:osrec_plan>)
  endif()
  if(OSREC_BUILD_EL0_ANALYZER)
    add_test(NAME el0_analysis COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_el0_analysis.py
      ${OSREC_OPT} $<TARGET_FILE:osrec_el0>)
    add_test(NAME el0_extraction COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_el0_extraction.py
      ${OSREC_OPT} $<TARGET_FILE:osrec_el0>)
    if(OSREC_BUILD_EL0_EXPORT_TESTS)
      find_program(OSREC_KLEE_EXECUTABLE NAMES klee REQUIRED)
      add_test(NAME el0_export COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_el0_export.py
        ${LLVM_TOOLS_BINARY_DIR} $<TARGET_FILE:osrec_el0>
        ${OSREC_KLEE_EXECUTABLE} ${OSREC_KLEE_INCLUDE})
      set_tests_properties(el0_export PROPERTIES TIMEOUT 180)
    endif()
  endif()
  if(OSREC_BUILD_LITEOS_KLEE_SCENARIO)
    find_program(OSREC_KLEE_EXECUTABLE NAMES klee REQUIRED)
    add_test(NAME read_observations COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_read_observations.py
      ${OSREC_LITEOS_SOURCE} ${CMAKE_C_COMPILER} $<TARGET_FILE:io_capture_tests>)
    set_tests_properties(read_observations PROPERTIES TIMEOUT 180)
    add_test(NAME syscall_checkpoints COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_syscall_checkpoint.py
      ${OSREC_LITEOS_SOURCE} ${CMAKE_C_COMPILER})
    set_tests_properties(syscall_checkpoints PROPERTIES TIMEOUT 240)
    add_test(NAME syscall_checkpoint_proof COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tools/verify_syscall_checkpoint.py
      --kernel-root ${OSREC_LITEOS_SOURCE} --out ${CMAKE_CURRENT_BINARY_DIR}/syscall-checkpoint-proof
      --llvm-bin ${OSREC_KLEE_LLVM_BIN} --klee ${OSREC_KLEE_EXECUTABLE}
      --klee-include ${OSREC_KLEE_INCLUDE})
    set_tests_properties(syscall_checkpoint_proof PROPERTIES TIMEOUT 180)
    add_test(NAME liteos_klee COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tools/klee_liteos.py
      --kernel-root ${OSREC_LITEOS_SOURCE}
      --out ${CMAKE_CURRENT_BINARY_DIR}/liteos-klee
      --llvm-bin ${OSREC_KLEE_LLVM_BIN}
      --klee-include ${OSREC_KLEE_INCLUDE}
      --klee ${OSREC_KLEE_EXECUTABLE} --run)
    set_tests_properties(liteos_klee PROPERTIES TIMEOUT 120)
    add_test(NAME liteos_trace_analysis COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_trace_analysis.py
      ${CMAKE_CURRENT_SOURCE_DIR}/tools/analyze_trace.py
      --kernel-root ${OSREC_LITEOS_SOURCE}
      --out ${CMAKE_CURRENT_BINARY_DIR}/liteos-trace-analysis
      --llvm-bin ${OSREC_KLEE_LLVM_BIN}
      --klee-include ${OSREC_KLEE_INCLUDE}
      --klee ${OSREC_KLEE_EXECUTABLE})
    set_tests_properties(liteos_trace_analysis PROPERTIES TIMEOUT 600)
    add_test(NAME standalone_sysread COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_standalone_sysread.py
      ${CMAKE_CURRENT_SOURCE_DIR}/tools/export_sysread.py
      ${CMAKE_CURRENT_BINARY_DIR}/liteos-trace-analysis/trace-plan.json
      ${OSREC_LITEOS_SOURCE} ${OSREC_KLEE_LLVM_BIN}/clang)
    set_tests_properties(standalone_sysread PROPERTIES DEPENDS liteos_trace_analysis TIMEOUT 180)
  endif()
  if(OSREC_BUILD_KERNEL_BINARY_REPLAY)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OSREC_GLIB REQUIRED glib-2.0)
    find_path(OSREC_QEMU_PLUGIN_INCLUDE qemu-plugin.h REQUIRED)
    add_library(osrec_footprint MODULE tools/qemu_plugins/footprint.c)
    set_target_properties(osrec_footprint PROPERTIES OUTPUT_NAME footprint PREFIX lib)
    target_include_directories(osrec_footprint PRIVATE ${OSREC_QEMU_PLUGIN_INCLUDE} ${OSREC_GLIB_INCLUDE_DIRS})
    target_compile_options(osrec_footprint PRIVATE -Wall -Wextra -Werror)
    if(APPLE)
      # QEMU resolves the plugin API when it loads the module.
      target_link_options(osrec_footprint PRIVATE -undefined dynamic_lookup)
    endif()
    add_test(NAME kernel_binary_replay COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_kernel_boundary.py)
    set_tests_properties(kernel_binary_replay PROPERTIES TIMEOUT 600
      ENVIRONMENT OSREC_FOOTPRINT_PLUGIN=$<TARGET_FILE:osrec_footprint>)
  endif()
  if(OSREC_BUILD_KLEE_STATE_BATCH)
    find_program(OSREC_KLEE_EXECUTABLE NAMES klee REQUIRED)
    find_program(OSREC_BATCH_QEMU_AARCH64 NAMES qemu-system-aarch64 REQUIRED)
    foreach(profile IN ITEMS file-io fd-control)
      foreach(tier IN LISTS OSREC_KLEE_STATE_BATCH_TIERS)
        set(manifest ${CMAKE_CURRENT_SOURCE_DIR}/integrations/linux_aarch64/${profile}/klee-state-batch.json)
        file(READ ${manifest} manifest_text)
        # A tier the manifest has no entries for has nothing to run.
        if(NOT manifest_text MATCHES "\"tier\": \"${tier}\"")
          continue()
        endif()
        add_test(NAME klee_state_batch_${profile}_${tier} COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/tools/klee_state_batch.py --manifest ${manifest}
          --work ${CMAKE_CURRENT_BINARY_DIR}/klee-state-batch-${profile}-${tier} --tier ${tier}
          --llvm-bin ${OSREC_KLEE_LLVM_BIN} --klee ${OSREC_KLEE_EXECUTABLE}
          --klee-include ${OSREC_KLEE_INCLUDE} --qemu ${OSREC_BATCH_QEMU_AARCH64})
        if(tier STREQUAL "quick")
          set_tests_properties(klee_state_batch_${profile}_${tier} PROPERTIES TIMEOUT 3600)
        else()
          set_tests_properties(klee_state_batch_${profile}_${tier} PROPERTIES TIMEOUT 21600)
        endif()
      endforeach()
    endforeach()
  endif()
endif()
