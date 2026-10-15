# 图片与文档元数据题
使用 metadata 只读适配器。保留 ExifTool 分组字段名，不合并同名的不同来源字段。
原件文件系统时间使用 OriginalFS 字段；ExifTool 的 System 字段属于工作副本，不能当作原件时间。
EXIF 无时区的时间保持原样，不自动认定为北京时间。缺失作者或 GPS 信息明确说明。
