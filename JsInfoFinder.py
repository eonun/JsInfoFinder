import os
import re
import optparse
import datetime
from prettytable import PrettyTable

class JsInfoFinder:
    def __init__(self):
        self.regex = {
            "Email": r"(([a-zA-Z0-9][_|\.])*[a-zA-Z0-9]+@([a-zA-Z0-9][-|_|\.])*[a-zA-Z0-9]+\.((?!js|css|jpg|jpeg|png|ico)[a-zA-Z]{2,}))",
            "Oss云存储桶": r"(([A|a]ccess[K|k]ey[I|i]d|[A|a]ccess[K|k]ey[S|s]ecret|[Aa]ccess-[Kk]ey)|[A|a]ccess[K|k]ey)\s*['\"]([0-9a-fA-F\-_=]{6,128})['\"]",
            "aliyun_oss_url": r"[\\w.]\\.oss.aliyuncs.com",
            "rsa_private_key": r"-----BEGIN RSA PRIVATE KEY-----",
            "ssh_dsa_private_key": r"-----BEGIN DSA PRIVATE KEY-----",
            "ssh_dc_private_key": r"-----BEGIN EC PRIVATE KEY-----",
            "pgp_private_block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "SSH_privKey": r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
            "json_web_token": r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$",
            "github_access_token": r"[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*",
            "slack_token": r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
            "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})?",
            "Square Access Token": r"sqOatp-[0-9A-Za-z\\-_]{22}",
            "JSON Web Token": r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|eyJ[A-Za-z0-9_\/+-]{10,}\.[A-Za-z0-9._\/+-]{10,})",
            "Shiro": r"(=deleteMe|rememberMe=)",
            "Swagger UI": r"((swagger-ui.html)|(\"swagger\":)|(Swagger UI)|(swaggerUi)|(swaggerVersion))",
            "Secret Key OR Password OR ID": r"(?i)\b((((api|aws|db|app|)secret(key|id|accesskey))|([a-z_]{3,32}[_-](key|apikey|secret|access|token|password|pass|passwd|id|sid|uid)))\s*(=|:)\s*['\"]([0-9a-zA-Z\-_=]{6,128})['\"])",
            "国内手机号码": r"[^\w]((?:(?:\+|00)86)?1(?:(?:3[\d])|(?:4[5-79])|(?:5[0-35-9])|(?:6[5-7])|(?:7[0-8])|(?:8[\d])|(?:9[189]))\d{8})[^\w]",
            "身份证号码": r"[^0-9]((\d{8}(0\d|10|11|12)([0-2]\d|30|31)\d{3}$)|(\d{6}(18|19|20)\d{2}(0[1-9]|10|11|12)([0-2]\d|30|31)\d{3}(\d|X|x)))[^0-9]",
            "IP地址": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            "Password": r"(?i)\b(pass(word|wd|)|userPassword)\b\s*[:=]\s*['\"]([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:.?\/]{6,64})['\"]",
            "Key_Key_Key_key": r"(secret|appkey|ossKey|accessKey)\s*(=|:)\s*['\"]{0,1}([0-9a-zA-Z\-_=]{6,64})['\"]{0,1}",
            "AuthorizationToken": r"(Authorization|Token)\s*(=|:)\s*['\"]([0-9a-zA-Z\-_=]{6,128})['\"]",
            "加解密密钥_IV": r"(?i)(key|k|iv|i)\s*(=|:)\s*['\"][A-Za-z0-9+/]{16,999}(={0,2}|)['\"]"
        }
        self.num = 0
        self.is_show = False
        self.table = PrettyTable(["序号", "类型", "内容", "文件路径"])

    def read_js(self, file_path):
        """读取文件内容"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read()
        except UnicodeDecodeError:
            try:
                with open(file_path, 'r', encoding='latin1') as file:
                    return file.read()
            except Exception as e:
                print(f"\033[31m [-] 读取文件{file_path}时发生错误: {e} \033[0m")
                return None
        except FileNotFoundError:
            print(f"\033[31m [-] 文件未找到: {file_path} \033[0m")
            return None
        except Exception as e:
            print(f"\033[31m [-] 读取文件{file_path}时发生错误: {e} \033[0m")
            return None

    def send_js(self, file_path):
        """处理单个JS文件"""
        try:
            js_content = self.read_js(file_path)
            if js_content is not None:
                self.search_js(js_content, file_path)
        except Exception as e:
            print(f"\033[31m [-] 处理文件时发生错误: {e} \033[0m")

    def search_js(self, js_script, url):
        """搜索JS内容中的敏感信息"""
        try:
            str_table = []
            str_len = len(js_script)

            for key, pattern in self.regex.items():
                match_start = 0
                reg_list = []
                while match_start < str_len:
                    reg_cont = js_script[match_start:str_len]
                    regex_result = re.search(pattern, reg_cont, re.IGNORECASE)
                    if regex_result:
                        match_start += regex_result.end() + 1
                        self.is_show = True
                        if regex_result.group() not in reg_list:
                            print("\033[32m [+] 发现\033[0m" + "\033[31m {} \033[0m".format(key) + "\033[32m 在 {} \033[0m".format(url))
                            self.num += 1
                            reg_list.append(regex_result.group())

                            str_table.append(str(self.num))
                            str_table.append(key)
                            str_table.append("`" + regex_result.group().strip() + "`")
                            str_table.append(url)
                            self.table.add_row(str_table)
                            str_table = []
                    else:
                        break
        except Exception as e:
            print(f"\033[31m [-] 搜索敏感信息时发生错误: {e} 在文件: {url} \033[0m")

    def print_table(self):
        """打印结果表格并保存到文件"""
        if self.is_show:
            print(self.table)
            date = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
            with open(date + '.md', 'w', encoding='utf-8') as file:
                markdown_table = "# 敏感信息泄露扫描结果\n"
                markdown_table += "| 序号 | 类型 | 内容 | 文件路径 |\n"
                markdown_table += "|---|---|---|---|\n"
                for row in self.table.rows:
                    markdown_table += "|".join(map(str, row)) + " |\n"
                file.write(markdown_table)
            print("\033[32m [+] 结果保存到 {} ！\033[0m".format(date + '.md'))
        else:
            print("\033[32m [!] 未发现敏感信息!\033[0m")

    def InfoFinder(self):
        """主函数，处理命令行参数并调用相应功能"""
        parser = optparse.OptionParser("python %prog -d /to/dir OR -f /path/to/file")
        parser.add_option('-d', '--directory', dest='directory', help='指定目录，读取目录及其子目录下的所有文件')
        parser.add_option('-f', '--file', dest='file', help='指定单个文件进行搜索')
        options, args = parser.parse_args()

        js_list = []
        if options.directory:
            directory = options.directory
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith('.js'):
                        js_list.append(os.path.join(root, file))
        elif options.file:
            js_list.append(options.file)
        else:
            parser.error("请使用 -d 指定目录或 -f 指定单个文件")

        print("\033[32m [+] 找到 %d 个 js 文件\033[0m" % (len(js_list)))
        print("\033[33m [+] 开始匹配！\033[0m")
        for js_file in js_list:
            self.send_js(js_file.strip())

        print("\033[33m [+] 共匹配到 %d 个结果\033[0m" % (self.num))
        self.print_table()

if __name__ == '__main__':
    finder = JsInfoFinder()
    finder.InfoFinder()
