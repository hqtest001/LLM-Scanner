@echo off
chcp 65001 >nul
echo ========================================
echo   LLM Scanner V1.0 打包工具
echo ========================================
echo.

echo [1/3] 检查 Python 环境...
python --version
if errorlevel 1 (
    echo 错误: 未找到 Python，请先安装 Python 3.8+
    pause
    exit /b 1
)

echo.
echo [2/3] 安装依赖...
pip install PySimpleGUI requests pyinstaller -q

echo.
echo [3/3] 开始打包...
pyinstaller --onefile --windowed --noconsole --name "LLM_Scanner_V1.0" --add-data "llm_scanner.py;." main.py

echo.
echo ========================================
if exist "dist\LLM_Scanner_V1.0.exe" (
    echo   打包成功!
    echo   输出文件位于: dist\LLM_Scanner_V1.0.exe
) else (
    echo   打包失败,请检查错误信息
)
echo ========================================
echo.
pause

