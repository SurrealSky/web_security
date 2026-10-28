MCP
=========================================

Windows-MCP
-----------------------------------------
+ 项目地址： ``https://github.com/CursorTouch/Windows-MCP``
+ 安装
    - 安装 uv ： ``https://github.com/astral-sh/uv/releases`` ,直接下载二进制放到system32目录
    - 安装 python 3.14
        ::

            # 使用阿里云镜像
            $env:UV_PYTHON_INSTALL_MIRROR = "https://registry.npmmirror.com/-/binary/python-build-standalone"

            # 然后再次尝试安装
            uv python install 3.14 --default

    - 先运行 ``uvx windows-mcp serve`` 安装依赖
+ 创建计划任务： ``windows-mcp install`` 
+ 修改计划任务
    - 权限指定最高权限
    - 触发器是administrator账户登录
    - 运行程序： ``powershell.exe``
    - 参数： ``-WindowStyle Hidden -Command "& {python.exe -m windows_mcp serve --transport sse --host 0.0.0.0 --port 9811 --auth-key "你的令牌"}"``
    - 这样开机就能自动启动。