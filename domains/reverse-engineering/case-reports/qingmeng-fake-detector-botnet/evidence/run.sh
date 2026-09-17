# 下载客户端
echo "正在下载客户端..."
wget -P /root http://wzjc.ipwz666.space/client -O /root/client

# 修改权限并运行
echo "正在修改文件权限并运行客户端..."
chmod 777 /root/client
/root/client