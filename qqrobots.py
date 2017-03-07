#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Time  : 2017/1/19 10:49
# @Author: lxflxf
# @File  : qqrobots.py
# @Ver   : 0.1

import requests
import logging
import json
from time import sleep


class QQlogin():
    """
    模拟qq机器人
    """
    # 获取二维码地址
    urlpngget = 'https://ssl.ptlogin2.qq.com/ptqrshow?appid=501004106&e=0&l=M&s=5&d=72&v=4&t=0.1'

    # 判断二维码是否失效地址
    judge_png_url = 'https://ssl.ptlogin2.qq.com/ptqrlogin?webqq_type=10&remember_uin=1&login2qq=1&aid=501004106 &u1=http%3A%2F%2Fw.qq.com%2Fproxy.html%3Flogin2qq%3D1%26webqq_type%3D10 &ptredirect=0&ptlang=2052&daid=164&from_ui=1&pttype=1&dumy=&fp=loginerroralert &action=0-0-157510&mibao_css=m_webqq&t=1&g=1&js_type=0&js_ver=10143&login_sig=&pt_randsalt=0'

    # 保存请求cookie等信息
    request_info = {}

    def __init__(self):
        pass

    def getPng(self):
        """
        获取登陆二维码图片
        :return:
        """

        r = requests.get(self.urlpngget)
        if r.status_code == 200:
            logging.debug('download successful')
            self.request_info['qrsig'] = r.headers['Set-Cookie'].split(';')[0].split('=')[1]
            print self.request_info
            with open('login.png', 'wb') as f:
                f.write(r.content)
        else:
            logging.warning('网络连接失败，状态码: %s' % r.status_code)

    def mainloop(self):
        """
        判断二维码状态：
        失效、 正在使用、登陆成功
        登陆成功后需要获取 ptwebqq、uin, psessionid、vfwebqq
        :return:
        """
        req = requests.Session()   # 同一个session请求，避免自己设置cookie
        r = req.get(self.judge_png_url, cookies={'qrsig': self.request_info['qrsig']})
        if r.status_code == 200:
            print r.content
            if '66' in r.content.split(',')[0]:
                print u'验证码未失效'
                return False
            if '65' in r.content.split(',')[0]:
                print u'验证码已失效'
                return False
            if '0' in r.content.split(',')[0]:
                print u'登陆成功'
                self.request_info['ptwebqq'] = r.headers['Set-Cookie'].split(',')[-1].split(';')[0].split('=')[1]
                self.request_info['ptlogin4.web2.qq.com'] = r.content.split(',')[2].strip('\'')
                self.getUin(req)
                self.getvfwebqq(req)
                self.getPsessionid(req)
                return True

    def getUin(self, req):
        """
        获取登陆后的uin参数
        :return:
        """
        # print req.cookies
        r = req.get(self.request_info['ptlogin4.web2.qq.com'])
        self.request_info['uin'] = requests.utils.dict_from_cookiejar(req.cookies)['uin']

    def getvfwebqq(self, req):
        """
        获取vfwebqq参数
        :param req:
        :return:
        """
        # 跨域请求需要处理cookie
        self.request_info['cookies'] = requests.utils.dict_from_cookiejar(req.cookies)
        getvfwebqq_url = 'http://s.web2.qq.com/api/getvfwebqq?ptwebqq=%s&clientid=53999199&psessionid=&t=0.1' % self.request_info['ptwebqq']
        print self.request_info['cookies']
        ###
        headers = {
            'Referer': 'http://s.web2.qq.com/proxy.html?v=20130916001&callback=1&id=1'
        }
        r = req.get(getvfwebqq_url, cookies=self.request_info['cookies'], headers=headers)
        vfwebqq = json.loads(r.content)
        self.request_info['vfwebqq'] = vfwebqq['result']['vfwebqq']

    def getPsessionid(self, req):
        """
        获取psessionid参数
        :param req:
        :return:
        """
        psessionid_url = 'http://d1.web2.qq.com/channel/login2'
        post_data = 'r=' + json.dumps({'ptwebqq': self.request_info['ptwebqq'],'clientid': 53999199, 'psessionid':'', 'status': 'online'})
        print post_data
        r = req.post(psessionid_url, data=post_data, cookies=self.request_info['cookies'])
        pessionid =  json.loads(r.content)['result']['psessionid']
        self.request_info['psessionid'] = pessionid

    def sendMessage(self):
        """
        发送消息
        :param req:
        :return:
        """
        send_url = 'http://d1.web2.qq.com/channel/send_qun_msg2'
        headers = {
            'Referer': 'https://d1.web2.qq.com/cfproxy.html?v=20151105001&callback=1'
        }
        post_data = 'r='+ json.dumps({
            'psessionid': self.request_info['psessionid'],
            'msg_id': 78720002,
            'clientid': 53999199,
            'face': 528,
            'content': "[\"from qq bot\", [\"font\", {\"name\": \"宋体\", \"size\": 10, \"style\": [0, 0, 0], \"color\": \"000000\"}]]",
            'group_uin' : 2710105137,
        })
        r = requests.post(send_url, data=post_data, cookies=self.request_info['cookies'], headers=headers)
        print "send status: %s" % r.status_code
        print 'get content: %s' % r.content
        print 'post data: %s' % post_data


def main():
    qq = QQlogin()
    qq.getPng()
    while True:
        sleep(2)
        result = qq.mainloop()
        if result:
            break
    for i in range(3):
        sleep(1)
        qq.sendMessage()


if __name__ == "__main__":
    main()