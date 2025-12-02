#!/bin/bash

# --- 配置 ---
# C++ 源文件名
SOURCE_FILE="Africa-2009-128.cpp"
# 要测试的参与方数量列表 (用空格分隔)
PARTICIPANT_COUNTS="4 8 12 16 20 24 28 32"
# 每个配置的运行次数，用于计算平均值
RUN_COUNT=10
# 编译后的可执行文件基础名称
EXECUTABLE_BASE_NAME="protocol_sim"

# --- 检查依赖 ---
# 检查 g++ 编译器
if ! command -v g++ &> /dev/null; then
    echo "错误: 未找到 'g++' 编译器。请确保已安装 GCC/G++。"
    exit 1
fi
# 检查 bc 计算器 (用于浮点数运算)
if ! command -v bc &> /dev/null; then
    echo "错误: 'bc' 命令未找到。请先安装 (例如，在Ubuntu上: sudo apt-get install bc)。"
    exit 1
fi
# 检查源文件是否存在
if [ ! -f "$SOURCE_FILE" ]; then
    echo "错误: 源文件 '${SOURCE_FILE}' 不存在于当前目录。"
    exit 1
fi

# --- 脚本主逻辑 ---
echo "开始性能基准测试 (每个配置运行 ${RUN_COUNT} 次)..."
echo ""

# 打印 Markdown 表格的表头
echo "| 参与方数量 | 运行状态 | 总 Key Exchange 时间 (平均) | 每用户 Key Exchange 时间 (平均) |"
echo "|--------------|------------|---------------------------------|-----------------------------------|"

# 遍历每一个指定的参与方数量
for i in $PARTICIPANT_COUNTS; do
    executable_name="${EXECUTABLE_BASE_NAME}_${i}"
    
    # 1. 编译 C++ 程序 (每个配置只需编译一次)
    g++ -o "$executable_name" "$SOURCE_FILE" -lcryptopp -std=c++17 -DNUM_PARTICIPANTS=${i} 2>/dev/null
    
    if [ $? -ne 0 ]; then
        # 如果编译失败
        echo "| ${i}            | ❌ 编译失败 | N/A                             | N/A                               |"
        continue
    fi

    # 初始化计时器和错误标志
    total_exchange_time=0.0
    has_error=false

    # 2. 多次运行程序以收集数据
    for (( j=1; j<=${RUN_COUNT}; j++ )); do
        # 运行并捕获输出
        output=$(./"$executable_name" 2>&1)
        
        # 提取 "Total Key Exchange computation time"
        exchange_time=$(echo "$output" | grep "Total Key Exchange computation time" | awk '{print $(NF-1)}')

        if [[ -z "$exchange_time" ]]; then
            # 如果无法提取时间 (可能程序崩溃或输出格式错误)
            has_error=true
            break
        fi
        
        # 累加总时间
        total_exchange_time=$(LC_NUMERIC=C echo "$total_exchange_time + $exchange_time" | bc)
    done

    # 3. 计算平均值并格式化输出
    if [ "$has_error" = true ]; then
        # 如果任何一次运行失败
        echo "| ${i}            | ❌ 运行失败 | N/A                             | N/A                               |"
    else
        # 计算总时间的平均值
        avg_total_exchange=$(LC_NUMERIC=C echo "scale=3; $total_exchange_time / $RUN_COUNT" | bc)
        
        # 计算每用户的平均时间
        avg_per_user_exchange=$(LC_NUMERIC=C echo "scale=3; $avg_total_exchange / $i" | bc)

        # 打印格式化的 Markdown 表格行
        echo "| ${i}            | ✅ 成功     | ${avg_total_exchange} ms              | ${avg_per_user_exchange} ms                  |"
    fi

    # 4. 清理编译后的可执行文件
    rm -f "$executable_name"
done

echo ""
echo "所有基准测试完成。"
