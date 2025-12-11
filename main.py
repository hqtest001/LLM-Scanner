#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM Scanner V1.0 - 主程序
本地LLM服务未授权访问扫描工具
支持主题切换：浅色(V6风格) / 暗黑(V7风格)
"""

import PySimpleGUI as sg
import threading
import json
from llm_scanner import LLMScanner, LLM_SERVICES

# ============ 版本信息 ============
VERSION = "1.0.0"
WINDOW_SIZE = (1050, 620)

# ============ 主题配置 ============

class ThemeConfig:
    """主题配置类 - 完全对应V6和V7"""
    
    # 浅色主题 - 对应V6
    LIGHT = {
        "name": "Light",
        "sg_theme": "GrayGrayGray",
        "accent": "#007ACC",
        "button": "#007ACC",
        "button_text": "white",
        "button_disabled": "#999999",
        "log_bg": "#2b2b2b",
        "log_text": "#e0e0e0",
        "text_hint": "gray",
        "progress_bar": None,  # 使用默认
        "color_map": {
            "info": "#e0e0e0",
            "success": "#00ff00", 
            "warning": "yellow",
            "error": "#ff6666"
        }
    }
    
    # 暗黑主题 - 对应V7
    DARK = {
        "name": "Dark",
        "sg_theme": "DarkBlack1",
        "accent": "#00BFFF",
        "button": "#1E90FF",
        "button_text": "#d4d4d4",
        "button_disabled": "#2d2d2d",
        "log_bg": "#0d0d0d",
        "log_text": "#d4d4d4",
        "text_hint": "#9a9a9a",
        "text_primary": "#d4d4d4",
        "text_secondary": "#9a9a9a",
        "bg_dark": "#0d0d0d",
        "bg_medium": "#1a1a1a",
        "bg_light": "#2d2d2d",
        "border": "#404040",
        "progress_bar": ("#00BFFF", "#2d2d2d"),
        "table_header_bg": "#2d2d2d",
        "table_alt_row": "#1a1a1a",
        "color_map": {
            "info": "#d4d4d4",
            "success": "#00ff00",
            "warning": "yellow", 
            "error": "#ff6666"
        }
    }


def get_current_theme():
    """获取当前主题配置"""
    try:
        with open("theme_config.json", "r") as f:
            config = json.load(f)
            return config.get("theme", "light")
    except:
        return "light"


def save_theme(theme_name):
    """保存主题配置"""
    try:
        with open("theme_config.json", "w") as f:
            json.dump({"theme": theme_name}, f)
    except:
        pass


def create_window(theme_name="light"):
    """创建主窗口 - 浅色对应V6，暗黑对应V7"""
    theme = ThemeConfig.DARK if theme_name == "dark" else ThemeConfig.LIGHT
    sg.theme(theme["sg_theme"])
    
    is_dark = theme_name == "dark"
    theme_button_text = "🌙 暗黑" if theme_name == "light" else "☀️ 浅色"
    
    # ========== 暗黑主题 (V7风格) ==========
    if is_dark:
        ACCENT = theme["accent"]
        BUTTON = theme["button"]
        BTN_TEXT = theme["text_primary"]
        BTN_DISABLED_BG = theme["bg_light"]
        BTN_DISABLED_TEXT = theme["text_secondary"]
        BG_DARK = theme["bg_dark"]
        BG_MEDIUM = theme["bg_medium"]
        BG_LIGHT = theme["bg_light"]
        TEXT_PRIMARY = theme["text_primary"]
        TEXT_SECONDARY = theme["text_secondary"]
        BORDER = theme["border"]
        
        config_frame = sg.Frame('扫描配置', [
            [sg.Text('扫描类型:', text_color=TEXT_PRIMARY)],
            [sg.Radio('单个IP', 'TARGET_TYPE', key='-SINGLE-', default=True, enable_events=True, text_color=TEXT_PRIMARY),
             sg.Radio('IP范围', 'TARGET_TYPE', key='-RANGE-', enable_events=True, text_color=TEXT_PRIMARY),
             sg.Radio('CIDR', 'TARGET_TYPE', key='-CIDR-', enable_events=True, text_color=TEXT_PRIMARY)],
            [sg.Text('目标地址:', text_color=TEXT_PRIMARY)],
            [sg.Input(key='-TARGET-', size=(35, 1), background_color=BG_MEDIUM, text_color=TEXT_PRIMARY)],
            [sg.Text('示例: 192.168.1.100', key='-HINT-', font=('Helvetica', 9), text_color=TEXT_SECONDARY)],
            [sg.HorizontalSeparator(color=BORDER)],
            [sg.Checkbox('启用全端口扫描检测vLLM', key='-FULL_SCAN-', default=False, text_color=TEXT_PRIMARY)],
            [sg.Text('(扫描1024-40000端口范围)', font=('Helvetica', 9), text_color=TEXT_SECONDARY)],
            [sg.HorizontalSeparator(color=BORDER)],
            [sg.Button('开始扫描', key='-START-', size=(15, 1), button_color=(BTN_TEXT, BUTTON)),
             sg.Button('停止扫描', key='-STOP-', size=(15, 1), disabled=True, button_color=(BTN_DISABLED_TEXT, BTN_DISABLED_BG))],
            [sg.Text('进度: 0%', key='-PROGRESS_TEXT-', size=(15, 1), text_color=ACCENT),
             sg.ProgressBar(100, orientation='h', size=(22, 20), key='-PROGRESS-', bar_color=(ACCENT, BG_LIGHT))],
        ], size=(400, 300), title_color=ACCENT, relief=sg.RELIEF_GROOVE)
        
        log_frame = sg.Frame('扫描日志', [
            [sg.Multiline(size=(85, 15), key='-LOG-', autoscroll=True, disabled=True,
                         font=('Consolas', 9), background_color=BG_DARK, text_color=TEXT_PRIMARY)],
            [sg.Button('清除日志', key='-CLEAR_LOG-', size=(10, 1), button_color=(BTN_TEXT, BUTTON))]
        ], title_color=ACCENT, relief=sg.RELIEF_GROOVE)
        
        result_headers = ['IP地址', '端口', '服务', '状态', '漏洞']
        result_frame = sg.Frame('扫描结果', [
            [sg.Table(values=[], headings=result_headers, key='-RESULTS-',
                     auto_size_columns=False, col_widths=[16, 9, 16, 11, 33],
                     num_rows=8, justification='left', enable_events=True,
                     select_mode=sg.TABLE_SELECT_MODE_BROWSE,
                     background_color=BG_DARK, text_color=TEXT_PRIMARY,
                     header_background_color=BG_LIGHT, header_text_color=ACCENT,
                     alternating_row_color=BG_MEDIUM)],
            [sg.Button('查看详情', key='-DETAILS-', size=(10, 1), button_color=(BTN_TEXT, BUTTON)),
             sg.Button('导出结果', key='-EXPORT-', size=(10, 1), button_color=(BTN_TEXT, BUTTON)),
             sg.Button('清除结果', key='-CLEAR-', size=(10, 1), button_color=(BTN_TEXT, BUTTON))]
        ], title_color=ACCENT, relief=sg.RELIEF_GROOVE)
        
        services_data = [[s['name'], str(s['ports']), ', '.join(s['paths'])] for s in LLM_SERVICES]
        services_frame = sg.Frame('支持检测的服务 (11种)', [
            [sg.Table(values=services_data, headings=['服务名称', '端口', '检测路径'],
                     key='-SERVICES-', auto_size_columns=False,
                     col_widths=[18, 15, 25], num_rows=5, justification='left',
                     background_color=BG_DARK, text_color=TEXT_PRIMARY,
                     header_background_color=BG_LIGHT, header_text_color=ACCENT,
                     alternating_row_color=BG_MEDIUM)]
        ], title_color=ACCENT, relief=sg.RELIEF_GROOVE)
        
        layout = [
            [sg.Text('LLM Scanner', font=('Helvetica', 20, 'bold'), text_color=ACCENT),
             sg.Text('本地LLM服务未授权访问扫描工具', font=('Helvetica', 12), text_color=TEXT_PRIMARY),
             sg.Push(),
             sg.Button(theme_button_text, key='-THEME-', size=(8, 1), button_color=(BTN_TEXT, BUTTON))],
            [sg.HorizontalSeparator(color=BORDER)],
            [sg.Column([[config_frame], [services_frame]], vertical_alignment='top'),
             sg.Column([[log_frame], [result_frame]])],
            [sg.HorizontalSeparator(color=BORDER)],
            [sg.Text(f'版本: {VERSION} | Python + PySimpleGUI | 主题: Dark', 
                    font=('Helvetica', 9), text_color=TEXT_SECONDARY)]
        ]
    
    # ========== 浅色主题 (V6风格) ==========
    else:
        ACCENT = theme["accent"]
        BUTTON = theme["button"]
        BTN_TEXT = theme["button_text"]
        HINT_COLOR = theme["text_hint"]
        LOG_BG = theme["log_bg"]
        LOG_TEXT = theme["log_text"]
        
        config_frame = sg.Frame('扫描配置', [
            [sg.Text('扫描类型:')],
            [sg.Radio('单个IP', 'TARGET_TYPE', key='-SINGLE-', default=True, enable_events=True),
             sg.Radio('IP范围', 'TARGET_TYPE', key='-RANGE-', enable_events=True),
             sg.Radio('CIDR', 'TARGET_TYPE', key='-CIDR-', enable_events=True)],
            [sg.Text('目标地址:')],
            [sg.Input(key='-TARGET-', size=(35, 1))],
            [sg.Text('示例: 192.168.1.100', key='-HINT-', font=('Helvetica', 9), text_color=HINT_COLOR)],
            [sg.HorizontalSeparator()],
            [sg.Checkbox('启用全端口扫描检测vLLM', key='-FULL_SCAN-', default=False)],
            [sg.Text('(扫描1024-40000端口范围)', font=('Helvetica', 9), text_color=HINT_COLOR)],
            [sg.HorizontalSeparator()],
            [sg.Button('开始扫描', key='-START-', size=(15, 1), button_color=(BTN_TEXT, BUTTON)),
             sg.Button('停止扫描', key='-STOP-', size=(15, 1), disabled=True)],
            [sg.Text('进度: 0%', key='-PROGRESS_TEXT-', size=(15, 1)),
             sg.ProgressBar(100, orientation='h', size=(22, 20), key='-PROGRESS-')],
        ], size=(400, 300))
        
        log_frame = sg.Frame('扫描日志', [
            [sg.Multiline(size=(85, 15), key='-LOG-', autoscroll=True, disabled=True,
                         font=('Consolas', 9), background_color=LOG_BG, text_color=LOG_TEXT)],
            [sg.Button('清除日志', key='-CLEAR_LOG-', size=(10, 1))]
        ])
        
        result_headers = ['IP地址', '端口', '服务', '状态', '漏洞']
        result_frame = sg.Frame('扫描结果', [
            [sg.Table(values=[], headings=result_headers, key='-RESULTS-',
                     auto_size_columns=False, col_widths=[16, 9, 16, 11, 33],
                     num_rows=8, justification='left', enable_events=True,
                     select_mode=sg.TABLE_SELECT_MODE_BROWSE,
                     alternating_row_color='#f0f0f0',
                     selected_row_colors=('white', BUTTON))],
            [sg.Button('查看详情', key='-DETAILS-', size=(10, 1)),
             sg.Button('导出结果', key='-EXPORT-', size=(10, 1)),
             sg.Button('清除结果', key='-CLEAR-', size=(10, 1))]
        ])
        
        services_data = [[s['name'], str(s['ports']), ', '.join(s['paths'])] for s in LLM_SERVICES]
        services_frame = sg.Frame('支持检测的服务 (11种)', [
            [sg.Table(values=services_data, headings=['服务名称', '端口', '检测路径'],
                     key='-SERVICES-', auto_size_columns=False,
                     col_widths=[18, 15, 25], num_rows=5, justification='left',
                     alternating_row_color='#f0f0f0',
                     selected_row_colors=('white', BUTTON))]
        ])
        
        layout = [
            [sg.Text('LLM Scanner', font=('Helvetica', 20, 'bold'), text_color=ACCENT),
             sg.Text('本地LLM服务未授权访问扫描工具', font=('Helvetica', 12)),
             sg.Push(),
             sg.Button(theme_button_text, key='-THEME-', size=(8, 1), button_color=(BTN_TEXT, BUTTON))],
            [sg.HorizontalSeparator()],
            [sg.Column([[config_frame], [services_frame]], vertical_alignment='top'),
             sg.Column([[log_frame], [result_frame]])],
            [sg.HorizontalSeparator()],
            [sg.Text(f'版本: {VERSION} | Python + PySimpleGUI | 主题: Light', 
                    font=('Helvetica', 9), text_color=HINT_COLOR)]
        ]
    
    window = sg.Window(f'LLM Scanner V{VERSION}', layout, finalize=True, resizable=True, size=WINDOW_SIZE)
    
    # 暗黑主题下设置输入框光标颜色与主体字体一致
    if is_dark:
        window['-TARGET-'].Widget.config(insertbackground='#d4d4d4')
    
    return window


def main():
    """主函数"""
    current_theme = get_current_theme()
    theme_config = ThemeConfig.DARK if current_theme == "dark" else ThemeConfig.LIGHT
    
    window = create_window(current_theme)
    scanner = LLMScanner()
    scan_thread = None
    results_data = []
    log_history = []  # 保存日志历史 [(text, level), ...]
    
    color_map = theme_config["color_map"]
    default_color = theme_config["log_text"]
    
    def update_hint():
        hints = {
            '-SINGLE-': '示例: 192.168.1.100',
            '-RANGE-': '示例: 192.168.1.1-192.168.1.254',
            '-CIDR-': '示例: 192.168.1.0/24'
        }
        for key, hint in hints.items():
            if window[key].get():
                window['-HINT-'].update(hint)
                break
    
    def run_scan():
        target = window['-TARGET-'].get().strip()
        target_type = "single" if window['-SINGLE-'].get() else ("range" if window['-RANGE-'].get() else "cidr")
        enable_full_scan = window['-FULL_SCAN-'].get()
        scanner.scan(target, target_type, enable_full_scan)
        
    while True:
        event, values = window.read(timeout=50)
        
        if event == sg.WIN_CLOSED:
            scanner.stop()
            break
        
        # 主题切换
        if event == '-THEME-':
            # 保存当前数据
            saved_target = values['-TARGET-']
            saved_single = values['-SINGLE-']
            saved_range = values['-RANGE-']
            saved_cidr = values['-CIDR-']
            saved_full_scan = values['-FULL_SCAN-']
            saved_log_history = log_history.copy()
            saved_progress = scanner.progress
            saved_results = results_data.copy() if results_data else []
            saved_scanning = scanner.scanning
            
            window.close()
            if current_theme == "light":
                current_theme = "dark"
            else:
                current_theme = "light"
            save_theme(current_theme)
            
            theme_config = ThemeConfig.DARK if current_theme == "dark" else ThemeConfig.LIGHT
            color_map = theme_config["color_map"]
            default_color = theme_config["log_text"]
            
            window = create_window(current_theme)
            
            # 恢复数据
            window['-TARGET-'].update(saved_target)
            window['-SINGLE-'].update(saved_single)
            window['-RANGE-'].update(saved_range)
            window['-CIDR-'].update(saved_cidr)
            window['-FULL_SCAN-'].update(saved_full_scan)
            # 重新渲染日志（带颜色）
            log_history = saved_log_history
            for log_text, log_level in log_history:
                window['-LOG-'].print(log_text, text_color=color_map.get(log_level, default_color))
            window['-PROGRESS-'].update(saved_progress)
            window['-PROGRESS_TEXT-'].update(f'进度: {saved_progress}%')
            if saved_results:
                results_data = saved_results
                table_data = [[r['ip'], r['port'], r['service'], r['status'], r['vulnerability']] for r in saved_results]
                window['-RESULTS-'].update(values=table_data)
            if saved_scanning:
                window['-START-'].update(disabled=True)
                window['-STOP-'].update(disabled=False)
            continue
            
        # 处理消息队列
        while not scanner.msg_queue.empty():
            try:
                msg_type, msg_data, msg_level = scanner.msg_queue.get_nowait()
                if msg_type == "log":
                    log_history.append((msg_data, msg_level))  # 保存日志历史
                    window['-LOG-'].print(msg_data, text_color=color_map.get(msg_level, default_color))
                elif msg_type == "progress":
                    window['-PROGRESS-'].update(msg_data)
                    window['-PROGRESS_TEXT-'].update(f'进度: {msg_data}%')
                elif msg_type == "done":
                    results_data = msg_data
                    table_data = [[r['ip'], r['port'], r['service'], r['status'], r['vulnerability']] for r in msg_data]
                    window['-RESULTS-'].update(values=table_data)
                    window['-START-'].update(disabled=False)
                    window['-STOP-'].update(disabled=True)
            except:
                break
            
        if event in ['-SINGLE-', '-RANGE-', '-CIDR-']:
            update_hint()
            
        if event == '-START-':
            target = values['-TARGET-'].strip()
            if not target:
                sg.popup_error('请输入目标地址')
                continue
            window['-START-'].update(disabled=True)
            window['-STOP-'].update(disabled=False)
            window['-PROGRESS-'].update(0)
            window['-PROGRESS_TEXT-'].update('进度: 0%')
            window['-LOG-'].update('')
            log_history.clear()  # 清空日志历史
            results_data = []
            window['-RESULTS-'].update(values=[])
            scan_thread = threading.Thread(target=run_scan, daemon=True)
            scan_thread.start()
            
        if event == '-STOP-':
            scanner.stop()
            
        if event == '-CLEAR_LOG-':
            window['-LOG-'].update('')
            log_history.clear()  # 清空日志历史
            
        if event == '-CLEAR-':
            results_data = []
            window['-RESULTS-'].update(values=[])
            
        if event == '-DETAILS-':
            selected = values['-RESULTS-']
            if selected and results_data:
                idx = selected[0]
                if idx < len(results_data):
                    r = results_data[idx]
                    detail_text = f"IP: {r['ip']}\n端口: {r['port']}\n服务: {r['service']}\n状态: {r['status']}\n漏洞: {r['vulnerability']}\n时间: {r['timestamp']}\nURL: {r['url']}\n\n详情:\n{r['details']}\n\n响应:\n{r['response']}"
                    sg.popup_scrolled(detail_text, title='漏洞详情', size=(60, 20))
                    
        if event == '-EXPORT-':
            if results_data:
                # 使用系统原生对话框，两个主题效果一致
                filename = sg.popup_get_file('保存结果', save_as=True, default_extension='.json', 
                                             file_types=(('JSON', '*.json'),), no_window=True)
                if filename:
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(results_data, f, ensure_ascii=False, indent=2)
                    sg.popup(f'已保存: {filename}')
            else:
                sg.popup('没有结果可导出')
                
    window.close()


if __name__ == '__main__':
    main()
