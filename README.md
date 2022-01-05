# 前言

将nginx和第3方模块制作成rpm，方便后续使用

# 制作过程

1. srpm
2. 构建参数添加第3方模块
3. yum-buildep安装rpms依赖的环境
4. rpm -ba 构建rpm