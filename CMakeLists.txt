cmake_minimum_required(VERSION 3.14)
project(HallOfFame)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(FetchContent)

FetchContent_Declare(ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
  GIT_TAG main 
)

FetchContent_MakeAvailable(ftxui)

add_executable(HallOfFame main.cpp)

target_link_libraries(HallOfFame
  PRIVATE ftxui::component
  PRIVATE ftxui::dom
  PRIVATE ftxui::screen
)