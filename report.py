# encoding=utf8
import requests
import json
import time
import datetime
import pytz
import re
import sys
import argparse
from bs4 import BeautifulSoup
import re
import base64
import os
class Report(object):
    def __init__(self, stuid, password, report_data_path, apply_data_path, emergency_data, baidu_ak, baidu_sk, dormitory_data):
        self.stuid = stuid
        self.password = password
        self.report_data_path = report_data_path
        self.apply_data_path = apply_data_path
        self.run_status = "OK"
        self.emergency_data = emergency_data.split(",")
        self.baidu_ak = baidu_ak
        self.baidu_sk = baidu_sk
        self.dormitory_data = dormitory_data.split(",")
    def report(self, session, getform):
        cookies = session.cookies
        data = getform.text
        data = data.encode('ascii','ignore').decode('utf-8','ignore')
        soup = BeautifulSoup(data, 'html.parser')
        token = soup.find("input", {"name": "_token"})['value']

        with open(self.report_data_path, "r+", encoding="utf-8") as f:
            data = f.read()
            data = json.loads(data)
            data["_token"]=token
            data["jinji_lxr"] = self.emergency_data[0]
            data["jinji_guanxi"] = self.emergency_data[1]
            data["jiji_mobile"] = self.emergency_data[2]
            data["juzhudi"] = self.dormitory_data[0]
            data["dorm_building"] = self.dormitory_data[1]
            data["dorm"] = self.dormitory_data[2]

        headers = {
            'authority': 'weixine.ustc.edu.cn',
            'origin': 'https://weixine.ustc.edu.cn',
            'upgrade-insecure-requests': '1',
            'content-type': 'application/x-www-form-urlencoded',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'referer': 'https://weixine.ustc.edu.cn/2020/home',
            'accept-language': 'zh-CN,zh;q=0.9',
            'Connection': 'close',
            'cookie': "PHPSESSID=" + cookies.get("PHPSESSID") + ";XSRF-TOKEN=" + cookies.get("XSRF-TOKEN") + ";laravel_session="+cookies.get("laravel_session"),
        }

        url = "https://weixine.ustc.edu.cn/2020/daliy_report"
        session.post(url, data=data, headers=headers)
        data = session.get("https://weixine.ustc.edu.cn/2020").text
        soup = BeautifulSoup(data, 'html.parser')
        pattern = re.compile("202[0-9]-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}")
        token = soup.find(
            "span", {"style": "position: relative; top: 5px; color: #666;"})
        flag = False
        if pattern.search(token.text) is not None:
            date = pattern.search(token.text).group()
            print("Latest report: " + date)
            date = date + " +0800"
            reporttime = datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S %z")
            timenow = datetime.datetime.now(pytz.timezone('Asia/Shanghai'))
            delta = timenow - reporttime
            if delta.days < 0:
                delta = reporttime - timenow
            print("{} second(s) difference.".format(delta.seconds))
            # print("{} second(s) before.".format(delta.seconds))
            if delta.seconds < 120:
                flag = True
        if flag == False:
            self.run_status = "REPORT FAILED"
            print("Report FAILED!")
        else:
            print("Report SUCCESSFUL!")
        return flag

    def login(self):
        url = "https://passport.ustc.edu.cn/login?service=http%3A%2F%2Fweixine.ustc.edu.cn%2F2020%2Fcaslogin"
        session = requests.Session()

        # get CAS_LT
        response = session.get(url)
        response = BeautifulSoup(response.content, 'html.parser')
        login_form = response.find_all(class_='loginForm form-style')[0]
        CAS_LT = login_form.find_next(id='CAS_LT')['value']
        # get validate code
        vcode = self.get_vcode(session)
        data = {
            'model': 'uplogin.jsp',
            'service': 'https://weixine.ustc.edu.cn/2020/caslogin',
            'username': self.stuid,
            'password': str(self.password),
            'warn': '',
            'showCode': '1',
            'CAS_LT': CAS_LT,
            'LT': vcode,
            'button': '',
        }

        session.post(url, data=data)

        print("login...")
        return session
    def get_vcode(self, session):
        print(self.baidu_ak, self.baidu_sk)
        host = 'https://aip.baidubce.com/oauth/2.0/token?grant_type=client_credentials&client_id=' + self.baidu_ak + '&client_secret=' + self.baidu_sk
        response = requests.get(host)
        access_token = response.json()['access_token']        
        response = session.get("https://passport.ustc.edu.cn/validatecode.jsp?type=login")
        image = response.content

        request_url = "https://aip.baidubce.com/rest/2.0/ocr/v1/numbers"
        # 二进制方式打开图片文件
        # f = open('img.png', 'rb')
        img = base64.b64encode(image)

        params = {"image":img}
        # access_token = '[调用鉴权接口获取的token]'
        request_url = request_url + "?access_token=" + access_token
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        response = requests.post(request_url, data=params, headers=headers)
        vcode = response.json()['words_result'][0]['words']
        return vcode
    def apply(self, session, getform):
        cookies = session.cookies
        data = getform.text
        data = data.encode('ascii','ignore').decode('utf-8','ignore')
        soup = BeautifulSoup(data, 'html.parser')
        token = soup.find("input", {"name": "_token"})['value']
        now = datetime.datetime.now(pytz.timezone('Asia/Shanghai'))
        start_date = now + datetime.timedelta(minutes = -5)
        start_date_str = datetime.datetime.strftime(start_date, "%Y-%m-%d %H:%M:%S")
        end_date = now
        end_date_str = datetime.datetime.strftime(end_date, "%Y-%m-%d ") + "23:59:59"
        with open(self.apply_data_path, "r+", encoding="utf-8") as f:
            data = f.read()
            data = json.loads(data)
            data["_token"] = token
            data["start_date"] = start_date_str
            data["end_date"] = end_date_str

        headers = {
            'authority': 'weixine.ustc.edu.cn',
            'origin': 'https://weixine.ustc.edu.cn',
            'upgrade-insecure-requests': '1',
            'content-type': 'application/x-www-form-urlencoded',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'referer': 'https://weixine.ustc.edu.cn/2020/apply/daliy/i?t=3',
            'accept-language': 'zh-CN,zh;q=0.9',
            'Connection': 'close',
            'cookie': "PHPSESSID=" + cookies.get("PHPSESSID") + ";XSRF-TOKEN=" + cookies.get("XSRF-TOKEN") + ";laravel_session="+cookies.get("laravel_session"),
        }

        url = "https://weixine.ustc.edu.cn/2020/apply/daliy/post"
        session.post(url, data=data, headers=headers)
        data = session.get("https://weixine.ustc.edu.cn/2020/apply_total").text

        pattern = re.compile(end_date_str)

        soup = BeautifulSoup(data, 'html.parser')
        if len(soup.find_all(string=pattern)) > 0:
            flag = True
        else:
            flag = False
        if flag == False:
            self.run_status = "APPLY FAILED"
            print("APPLY FAILED!")
        else:
            print("APPLY SUCCESSFUL!")
        return flag


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='URC nCov auto report script.')
    parser.add_argument('report_data_path', help='path to your own data used for post method', type=str)
    parser.add_argument('apply_data_path', help='path to your own data used for post method', type=str)
    parser.add_argument('stuid', help='your student number', type=str)
    parser.add_argument('password', help='your CAS password', type=str)
    parser.add_argument('emergency_data', help='emergency data', type=str)
    parser.add_argument('baidu_ak', help='baidu api key', type=str)
    parser.add_argument('baidu_sk', help='baidu api secret key', type=str)
    parser.add_argument('dormitory_data', help='dormitory data, "campus,building_no,room_no"', type=str)

    args = parser.parse_args()
    autorepoter = Report(stuid=args.stuid, password=args.password, report_data_path=args.report_data_path, apply_data_path=args.apply_data_path,\
                    emergency_data=args.emergency_data, baidu_ak=args.baidu_ak, baidu_sk=args.baidu_sk, dormitory_data=args.dormitory_data)
    LOGIN_TIMES = 2
    REPORT_TIMES = 5
    APPLY_TIMES = 5
    loginsuccess = False
    count = LOGIN_TIMES
    while count != 0:
        session = autorepoter.login()
        getform_report = session.get("https://weixine.ustc.edu.cn/2020")
        getform_apply = session.get("https://weixine.ustc.edu.cn/2020/apply/daliy/i?t=3")

        if getform_report.url == "https://weixine.ustc.edu.cn/2020/home":
            loginsuccess = True
            break
        print("Login Failed, retry...")
        count = count - 1
    if loginsuccess:
        count = REPORT_TIMES
    else:
        print("Login Failed " + str(LOGIN_TIMES) + " times")
    reportsuccess = False
    while count != 0:
        reportsuccess = autorepoter.report(session, getform_report)
        if reportsuccess != False:
            break
        print("Report Failed, retry...")
        count = count - 1
    if reportsuccess:
        count = APPLY_TIMES
    applysuccess = False
    while count != 0:
        applysuccess = autorepoter.apply(session, getform_apply)
        if applysuccess != False:
            break
        print("Apply Failed, retry...")
        count = count - 1
    if applysuccess:
        exit(0)
    
    # last run info
    if(not loginsuccess):
        exit_code = 16
    elif(autorepoter.run_status == "REPORT FAILED"):
        exit_code = 32
    elif(autorepoter.run_status == "APPLY FAILED"):
        exit_code = 64
    else:
        exit_code = 128
    exit(exit_code)