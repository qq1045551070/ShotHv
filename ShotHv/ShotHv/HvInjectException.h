#pragma once

// @explain: 注入中断指令
	// @parameter: InterruptionType interruption_type	中断类型
	// @parameter: InterruptionVector vector	中断向量号		 	
	// @parameter: bool deliver_error_code		是否有错误码
	// @parameter: ULONG32 error_code			有的话请填写
	// @return:  void	不返回任何值
void InjectInterruption(
	_In_ InterruptionType interruption_type,
	_In_ InterruptionVector vector,
	_In_ BOOLEAN deliver_error_code,
	_In_ ULONG32 error_code
);

// 启用 MTF
void EnableMTF();

// 关闭 MTF
void DisableMTF();

// 开启 TF 单步调试功能
void EnableTF();

// 关闭 TF 单步调试功能
void DisableTF();
