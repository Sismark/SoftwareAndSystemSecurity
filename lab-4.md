# 实验四
---
## 实验要求
* 通过调试器监控计算器程序的运行，每当运行结果为666时，就改为999。

## 实验环境
* Microsoft Windows [version 6.1.7601]
* vs2017
* windbg 6.12

## 实验过程
* 修改运行结果其实就是修改屏幕显示的数字，在Windows中SetWindowText函数改变指定窗口的标题栏的文本内容，可以发现函数的第二个参数即是指向要显示字符的指针。
* 函数介绍：

```bash
# Changes the text of the specified window's title bar (if it has one). 
# If the specified window is a control, the text of the control is changed. 
# However, SetWindowText cannot change the text of a control in another application.
BOOL SetWindowTextA(
  HWND   hWnd, # A handle to the window or control whose text is to be changed.
  LPCSTR lpString # The new title or control text.
);
```	

* 使用windbg调试32位计算器(`C:\Windows\SysWOW64\calc.exe`)
* 对函数`SetWindowTextW`下断点，在参数入栈之后进行字符串判断及修改。
	* 需要修改的参数是`LPCSTR`,入栈后参数位置是`[esp+8]`
* 在windbg中执行脚本进行参数判断及修改

```bash
# 编写脚本，保存到C:\\chap4.txt
as /mu ${/v:LPCSTR} poi(esp+8)  
.if($scmp(@"${LPCSTR}","666")==0){ezu poi(esp+8) "999";}
g

# windbg内下断点，执行脚本
bp SetWindowTextW "$<C:\\chap4.txt"

# 继续运行计算器
g
```