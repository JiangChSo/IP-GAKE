#!/bin/bash

#
# 这个脚本用于自动编译、运行并分析单一协议模拟程序在不同用户规模下的数据大小开销。
# 它会为每个指定的用户组规模执行以下操作：
# 1. 使用 -D 编译标志来设置 C++ 源码中的 NUM_PARTICIPANTS 宏。
# 2. 编译指定的 C++ 源文件。
# 3. 运行编译后的程序。
# 4. 从输出中提取存储开销和三轮广播的通信开销。
# 5. 将所有结果格式化为 Markdown 表格输出。
#
# 用法:
# ./analyze_data_size.sh <源文件名.cpp>
# 例如: ./analyze_data_size.sh Grade80.cpp
#

# --- 配置 ---
SOURCE_DIR="../Data_Size"
# 定义要测试的用户数量列表
USER_COUNTS=(4 8 16 32 64 128)

# --- 检查输入参数 ---
if [ "$#" -ne 1 ]; then
    echo "错误: 请提供一个 C++ 源文件名作为参数。"
    echo "用法: $0 <源文件名.cpp>"
    exit 1
fi

SOURCE_FILE_NAME=$1
FULL_SOURCE_PATH="${SOURCE_DIR}/${SOURCE_FILE_NAME}"

if [ ! -f "$FULL_SOURCE_PATH" ]; then
    echo "错误: 源文件 ${FULL_SOURCE_PATH} 不存在。"
    exit 1
fi

# --- 脚本主逻辑 ---
echo "开始为 ${SOURCE_FILE_NAME} 进行数据大小分析..."
echo ""
echo "| 参与方数量 | 存储开销 (Bytes) | R1 广播 (Bytes) | R2 广播 (Bytes) | R3 广播 (Bytes) |"
echo "|--------------|--------------------|-------------------|-------------------|-------------------|"

for i in "${USER_COUNTS[@]}"; do
    # 为每个用户数量定义一个临时的可执行文件名
    executable="${SOURCE_DIR}/temp_exec_${i}"

    # 编译 C++ 文件，通过 -D 标志传递用户数量，并链接 cryptopp 库
    g++ -std=c++17 -DNUM_PARTICIPANTS=${i} -o "$executable" "$FULL_SOURCE_PATH" -lcryptopp
    if [ $? -ne 0 ]; then
        printf "| %-12d | %-18s | %-17s | %-17s | %-17s |\n" "${i}" "错误: 编译失败" "" "" ""
        continue
    fi

    # 运行一次程序以获取数据大小
    output=$(LC_NUMERIC=C ./"$executable" 2>&1)
    if [ $? -ne 0 ]; then
        printf "| %-12d | %-18s | %-17s | %-17s | %-17s |\n" "${i}" "错误: 程序运行时崩溃" "" "" ""
        rm -f "$executable" # 清理
        continue
    fi
    
    # 提取四个不同的数据大小指标
    storage_size=$(echo "$output" | grep "Stored FILE\[sid\] size:" | awk '{print $(NF-1)}')
    r1_size=$(echo "$output" | grep "Round 1 broadcast size:" | awk '{print $(NF-1)}')
    r2_size=$(echo "$output" | grep "Round 2 broadcast size:" | awk '{print $(NF-1)}')
    r3_size=$(echo "$output" | grep "Round 3 broadcast size:" | awk '{print $(NF-1)}')

    if [[ -z "$storage_size" || -z "$r1_size" || -z "$r2_size" || -z "$r3_size" ]]; then
        printf "| %-12d | %-18s | %-17s | %-17s | %-17s |\n" "${i}" "错误: 无法提取数据" "" "" ""
        rm -f "$executable" # 清理
        continue
    fi

    # 格式化输出
    printf "| %-12d | %-18s | %-17s | %-17s | %-17s |\n" "${i}" "${storage_size}" "${r1_size}" "${r2_size}" "${r3_size}"

    # 清理本次生成的可执行文件
    rm -f "$executable"
done

echo ""
echo "分析完成。"
