#!/bin/bash

#
# 这个脚本用于自动编译、运行并分析多个安全等级下协议模拟程序的性能。
# 它会按顺序为每个安全等级（80, 112, 128-bit）执行以下操作：
# 1. 查找对应的源文件（例如 Grade80.cpp）。
# 2. 为每个指定的用户组规模，编译并运行程序若干次。
# 3. 从输出中提取 Setup 和 Key Exchange 阶段的计算时间。
# 4. 计算平均时间，并格式化为 Markdown 表格输出。
#

# --- 配置 ---
BASE_SOURCE_DIR="../Time" # 源文件的基础目录
RUN_COUNT=20
# 要测试的用户组规模列表
PARTICIPANT_COUNTS="4 8 12 16 20 24 28 32"
# 要测试的安全等级列表
SECURITY_LEVELS="80 112 128"

# --- 检查依赖 ---
if ! command -v bc &> /dev/null; then
    echo "错误: 'bc' 命令未安装。请先安装它 (例如，在Ubuntu上运行: sudo apt-get install bc)"
    exit 1
fi
if [ ! -d "$BASE_SOURCE_DIR" ]; then
    echo "错误: 基础目录 ${BASE_SOURCE_DIR} 不存在。"
    exit 1
fi

# --- 脚本主逻辑 ---
echo "开始性能测试 (每个配置运行 ${RUN_COUNT} 次)..."
echo ""

# 遍历每一个安全等级
for level in $SECURITY_LEVELS; do
    echo "======================================================================================="
    echo "### 安全等级: ${level}-bit"
    echo "======================================================================================="
    echo ""

    SOURCE_DIR="${BASE_SOURCE_DIR}"
    SOURCE_FILENAME="Grade${level}.cpp"
    source_file="${SOURCE_DIR}/${SOURCE_FILENAME}"
    
    # 检查该安全等级的源文件是否存在
    if [ ! -f "$source_file" ]; then
        echo "警告: 未找到源文件 ${source_file}，跳过 ${level}-bit 等级的测试。"
        echo ""
        continue
    fi

    # 打印该等级的 Markdown 表头
    echo "| 参与方数量 | 平均 Setup 时间 | 平均 Key Exchange 时间 | 平均每用户 Setup 时间 | 平均每用户 Key Exchange 时间 |"
    echo "|--------------|-------------------|--------------------------|-------------------------|-------------------------------|"

    # 遍历每个参与方数量
    for i in $PARTICIPANT_COUNTS; do
        executable_name="test_app_${level}_${i}"
        executable_path="${SOURCE_DIR}/${executable_name}"

        # 编译 C++ 程序, 通过 -D 标志传入参与方数量
        g++ -std=c++17 -o "$executable_path" "$source_file" -lcryptopp -DNUM_PARTICIPANTS=${i}
        if [ $? -ne 0 ]; then
            echo "| ${i} | 错误: 编译失败 | | | |"
            continue
        fi

        total_setup_time=0.0
        total_exchange_time=0.0
        has_error=false

        for (( j=1; j<=${RUN_COUNT}; j++ )); do
            output=$(LC_NUMERIC=C ./"$executable_path" 2>&1)
            if [ $? -ne 0 ]; then
                echo "| ${i} | 错误: 程序运行时崩溃 | | | |"
                has_error=true
                break
            fi

            setup_time=$(echo "$output" | grep "Total Setup computation time" | awk '{print $(NF-1)}')
            exchange_time=$(echo "$output" | grep "Total Key Exchange computation time" | awk '{print $(NF-1)}')

            if [[ -z "$setup_time" || -z "$exchange_time" ]]; then
                echo "| ${i} | 错误: 无法提取时间 | | | |"
                has_error=true
                break
            fi

            total_setup_time=$(LC_NUMERIC=C echo "$total_setup_time + $setup_time" | bc)
            total_exchange_time=$(LC_NUMERIC=C echo "$total_exchange_time + $exchange_time" | bc)
        done

        if [ "$has_error" = true ]; then
            rm -f "$executable_path"
            continue
        fi

        # 计算总的平均时间
        avg_setup=$(LC_NUMERIC=C echo "scale=3; $total_setup_time / $RUN_COUNT" | bc)
        avg_exchange=$(LC_NUMERIC=C echo "scale=3; $total_exchange_time / $RUN_COUNT" | bc)

        # 计算平均到每个用户的 Setup 时间
        avg_setup_per_user=$(LC_NUMERIC=C echo "scale=3; $avg_setup / $i" | bc)
        
        # 计算平均到每个用户的 Key Exchange 时间
        avg_exchange_per_user=$(LC_NUMERIC=C echo "scale=3; $avg_exchange / $i" | bc)

        # 在输出行中加入所有计算结果
        echo "| ${i} | ${avg_setup} ms | ${avg_exchange} ms | ${avg_setup_per_user} ms | ${avg_exchange_per_user} ms |"

        # 清理编译后的可执行文件
        rm -f "$executable_path"
    done
    echo "" # 在每个表格后添加一个空行
done

echo "所有测试完成。"
