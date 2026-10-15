---
name: Forensic Agent
description: 冷白、冷灰与靛蓝的本地取证工作台
colors:
  accent: "#4353bd"
  accent-hover: "#33439f"
  accent-tint: "#edf0ff"
  bg: "#f3f5f8"
  paper: "#fff"
  ink: "#202a3b"
  muted: "#59677b"
  line: "#dce1e9"
  danger: "#a32435"
  success: "#246149"
typography:
  headline:
    fontFamily: '"Segoe UI","Microsoft YaHei UI","Microsoft YaHei",sans-serif'
    fontSize: "25px"
    fontWeight: 650
    lineHeight: 1.4
    letterSpacing: "-.025em"
  title:
    fontSize: "16px"
    fontWeight: 650
  body:
    fontFamily: '"Segoe UI","Microsoft YaHei UI","Microsoft YaHei",sans-serif'
    fontSize: "14px"
    lineHeight: 1.6
  label:
    fontSize: "13px"
    fontWeight: 600
  mono:
    fontFamily: 'Consolas,"Microsoft YaHei",monospace'
    fontSize: "12px"
    lineHeight: 1.7
rounded:
  workbench: "12px"
  control: "7px"
  status: "5px"
spacing:
  control-x: "12px"
  control-y: "10px"
  intake: "28px"
  report: "28px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.paper}"
    rounded: "{rounded.control}"
    padding: "8px 12px"
    height: "44px"
  button-primary-hover:
    backgroundColor: "{colors.accent-hover}"
  button-secondary:
    backgroundColor: "{colors.paper}"
    textColor: "#344056"
    rounded: "{rounded.control}"
    padding: "8px 12px"
  button-quiet:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    rounded: "{rounded.control}"
    padding: "8px 12px"
  input:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "10px 12px"
  status:
    backgroundColor: "#eef1f5"
    textColor: "{colors.muted}"
    rounded: "{rounded.status}"
    padding: "3px 9px"
  workbench:
    backgroundColor: "{colors.paper}"
    rounded: "{rounded.workbench}"
---

# Design System: Forensic Agent

## Overview

**Creative North Star: "本地实验工作台"**

以已实现的本地实验工作台为依据：冷白纸面承载检材输入与可复核报告，靛蓝集中标记操作和选择状态，文字与细分隔线组织高密度信息。

使用系统字体、内联线性 SVG 和本地样式脚本；离线界面不依赖外部字体、图片或资源。

**Key Characteristics:**

- 冷白与冷灰底层，靛蓝操作重点
- 单列输入，使用后展开报告，步骤与依据可追踪
- 细边框、轻圆角、无阴影

## Colors

### Primary

靛蓝 accent 用于主操作、当前页签、焦点和单选控件；accent-hover 加深悬停反馈，accent-tint 承载信息与运行状态。

### Neutral

冷灰 bg 包围白色 paper 工作台；ink 用于正文，muted 承载次级信息，line 划分输入、报告和运行记录。

成功与失败使用 success、danger 语义色并配状态文字；告警使用浅红底，信息使用浅靛蓝底。

## Typography

系统无衬线字体兼顾中文与英文；Consolas 与中文等宽后备字体用于原始输出、参数和代码。标题使用紧凑字距与中等偏粗字重。页标题使用 headline；面板标题使用 title；标签使用 label。帮助文字和按钮多为（12px），报告正文为（13px / 1.8），阅读宽度上限为（78ch）。移动页标题缩至（23px）。

## Layout

主容器居中，上限（960px），常规左右留白（28px）。单列工作台只在主流程显示检材与题目两项输入；题目框最小高度（190px）。模型说明与开始按钮横向排列，按钮位于右侧。高级选项和历史案件默认折叠；运行任务或查看历史时在输入区下方展开结果。输入与报告内边距均为（28px）。

至多（760px）页面左右留白（16px），工作台内容留白（22px）；开始按钮全宽，本机徽标隐藏，页脚纵向排列。报告长文本换行，表格最小宽度（450px）并在局部容器横向滚动。工具参数、历史记录与日志使用有界滚动区。

## Elevation & Depth

无阴影。深度来自白纸面、淡灰输入区、细边框和分隔线；工具输出使用浅灰填充，报告保持纸面阅读感。

## Shapes

工作台大圆角使用 workbench；输入框、按钮、提示和代码块使用 control；状态条使用 status。线性 SVG 图标与细边框相配，圆点仅承担连接、日志或旋转进度提示。

## Components

主按钮最小宽度（152px）、最小高度（44px），窄屏全宽；次按钮与安静按钮最小高度（36px），禁用时透明度（0.5）并显示禁用光标。主流程默认由本地模型选工具；高级选项通过原生 details/summary 折叠，内含执行方式、手动工具与环境检查。

输入带可见标签和帮助文本，焦点为靛蓝双像素轮廓；按钮、链接和折叠摘要使用三像素轮廓与外偏移。题目框参考“题目、检材背景、时间/时区、答案格式、已尝试步骤”，不增加独立必填表单；超长输入保持原文，用计数与原生验证提示拆分。状态条区分等待、运行、完成、失败；运行态保留进度文字。业务告警与连接告警各有独立 alert 区域。报告操作在报告可用后出现，运行记录可折叠。

控件颜色和边框过渡为（0.16s ease-out）；进度环为（1s linear）旋转。prefers-reduced-motion 禁用动画与过渡，并把进度环改为静态点状边框。图标内联 SVG 且装饰图标对辅助技术隐藏。

## Do's and Don'ts

### Do:

- Do 保持标签、帮助文本和明确的状态文字。
- Do 保留键盘焦点、原生表单语义和减少动画支持。
- Do 让长路径换行、宽报告表格在自身容器横向滚动。

### Don't:

- Don't 用颜色代替运行、完成或失败的文字。
- Don't 为现有离线界面引入外部字体、图标或图片依赖。
