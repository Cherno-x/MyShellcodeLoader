# Reflective DLL Injection

### RDI

https://github.com/stephenfewer/ReflectiveDLLInjection

通过reflective loader可以直接从内存中加载pe library，无需通过磁盘加载;可以绕过一些av的file scan；

反射dll是一种特质的动态库，可以通过relfective loader 加载执行，无需使用LoadLibraryA加载dll文件。

本质就是自实现的LoadLibraryA函数，并可以做更多的调整。

createremotethread的入口点需要计算reflective loader的偏移量

可以修改关键字来避免字符串检测。main.cpp和ReflectiveLoader.c