#导入程序运行必须模块
import sys
#PyQt5中使用的基本控件都在PyQt5.QtWidgets模块中
from PyQt5.QtWidgets import QApplication, QMainWindow
#导入designer工具生成的login模块
from socket_ui import Ui_MainWindow
import socket

class MyMainForm(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super(MyMainForm, self).__init__(parent)
        self.setupUi(self)
        #添加登录按钮信号和槽。注意display函数不加小括号()
        self.pushButton.clicked.connect(self.send)
        #添加退出按钮信号和槽。调用close函数
        self.pushButton_3.clicked.connect(self.close)
    def send(self):
        ip = self.lineEdit.text()
        port = self.lineEdit_2.text()
        ip_port = (ip, int(port))
        sk = socket.socket()  # 创建套接字
        sk.bind(ip_port)  # 绑定服务地址
        sk.listen(5)  # 监听连接请求
        print('启动socket服务，等待客户端连接...')
        conn, address = sk.accept()  # 等待连接，此处自动阻塞
        while True:  # 一个死循环，直到客户端发送‘exit’的信号，才关闭连接
            client_data = conn.recv(1024).decode()  # 接收信息
            if client_data == "exit":  # 判断是否退出连接
                exit("通信结束")
            print("来自%s的客户端向你发来信息：%s" % (address, client_data))
            self.lineEdit_3.setText("来自%s的客户端向你发来信息：%s" % (address, client_data))
            conn.sendall('服务器已经收到你的信息'.encode())  # 回馈信息给客户端
        conn.close()  # 关闭连接
    # def display(self):
    #     #利用line Edit控件对象text()函数获取界面输入
    #     username = self.user_lineEdit.text()
    #     password = self.pwd_lineEdit.text()
    #     #利用text Browser控件对象setText()函数设置界面显示
    #     self.user_textBrowser.setText("登录成功!\n" + "用户名是: "+ username+ ",密码是： "+ password)

if __name__ == "__main__":
    #固定的，PyQt5程序都需要QApplication对象。sys.argv是命令行参数列表，确保程序可以双击运行
    app = QApplication(sys.argv)
    #初始化
    myWin = MyMainForm()
    #将窗口控件显示在屏幕上
    myWin.show()
    #程序运行，sys.exit方法确保程序完整退出。
    sys.exit(app.exec_())