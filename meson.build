project('ARMORY_EXAMPLE', 'cpp',
 version : '0.1',
 default_options : ['warning_level=3', 'cpp_std=c++17', 'b_lto=true'])

message(get_option('buildtype'), 'build')

libarmory_cli_dep = subproject('armory_cli').get_variable('libarmory_cli_dep')

executable('armory_example',
    sources: files('src/main.cpp'),
    include_directories : [include_directories('include'), include_directories('include/ELFIO')],
    dependencies: libarmory_cli_dep)

