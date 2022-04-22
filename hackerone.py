# -*- coding:utf-8 -*-
import os
import time
import json
import requests
import hashlib
from datetime import datetime, timedelta

DINGTALK_TOKEN = os.environ.get('DINGTALK_TOKEN')
COUNT = 20 # 默认查询数量

LEVEL = {
	"none": u"无影响",
	"low": u"低危",
	"medium": u"中危",
	"high": u"高危",
	"critical": u"严重"
}

def check(t):
	date_format = "%Y-%m-%dT%H:%M:%S.%fZ"
	update = datetime.strptime(t, date_format)
	now = datetime.strptime(str(datetime.now().strftime(date_format)), date_format)
	delta = now - update
	# 每天运行一次，仅输出近一天内的更新
	if delta.days == 0:
		return True
	return False

def get_info():
	url = "https://hackerone.com/graphql"

	headers = {
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0",
		"Content-Type": "application/json"
	}
	data = """{"operationName":"HacktivityPageQuery","variables":{"querystring":"","where":{"report":{"disclosed_at":{"_is_null":false}}},"orderBy":null,"secureOrderBy":{"latest_disclosable_activity_at":{"_direction":"DESC"}},"count":%d,"maxShownVoters":10},"query":"query HacktivityPageQuery($querystring: String, $orderBy: HacktivityItemOrderInput, $secureOrderBy: FiltersHacktivityItemFilterOrder, $where: FiltersHacktivityItemFilterInput, $count: Int, $cursor: String) {\\n  hacktivity_items(\\n    first: $count\\n    after: $cursor\\n    query: $querystring\\n    order_by: $orderBy\\n    secure_order_by: $secureOrderBy\\n    where: $where\\n  ) {\\n ...HacktivityList\\n}\\n}\\n\\nfragment HacktivityList on HacktivityItemConnection {\\n edges {\\n    node {\\n   ... on HacktivityItemInterface {\\n  ...HacktivityItem\\n}\\n    }\\n  }\\n}\\n\\nfragment HacktivityItem on HacktivityItemUnion {\\n  ... on Undisclosed {\\n    ...HacktivityItemUndisclosed\\n  }\\n  ... on Disclosed {\\n    ...HacktivityItemDisclosed\\n  }\\n  ... on HackerPublished {\\n    ...HacktivityItemHackerPublished\\n  }\\n}\\n\\nfragment HacktivityItemUndisclosed on Undisclosed {\\n  reporter {\\n    username\\n  }\\n  team {\\n    name\\n}\\n  latest_disclosable_activity_at\\n  requires_view_privilege\\n  total_awarded_amount\\n}\\n\\nfragment HacktivityItemDisclosed on Disclosed {\\n  team {\\n    name\\n}\\n  report {\\n    title\\n    url\\n  }\\n  latest_disclosable_activity_at\\n  total_awarded_amount\\n  severity_rating\\n}\\n\\nfragment HacktivityItemHackerPublished on HackerPublished {\\n  team {\\n    name\\n}\\n  report {\\n    url\\n    title\\n}\\n  latest_disclosable_activity_at\\n  severity_rating\\n}\\n"}"""
	req = requests.post(url, headers=headers, data=data % COUNT, timeout=5)

	edges = req.json()["data"]["hacktivity_items"]["edges"]
	for edge in edges:
		title = edge["node"]["report"]["title"]
		url = edge["node"]["report"]["url"]
		_level = edge["node"]["severity_rating"]
		vendor = edge["node"]["team"]["name"]
		bounty = edge["node"]["total_awarded_amount"] if edge["node"]["total_awarded_amount"] != None else 0.0
		disclosable_time = edge["node"]["latest_disclosable_activity_at"]
		cn_title = translate(title)
		if check(disclosable_time):
			msg = u"# 每日HackerOne漏洞推送\n\n\[%s\][%s](%s)\n\n> %s\n\n- %s\n- %s\n- $%d" % (LEVEL[_level],title,url,cn_title,vendor,disclosable_time,bounty)
			print(title,url,_level,vendor,bounty,disclosable_time)
			send_message(msg)

def send_message(msg):
	api_url = "https://oapi.dingtalk.com/robot/send?access_token="+DINGTALK_TOKEN
	data = {
		"msgtype": "markdown",
		"markdown": {
			"text": msg,
			"title": "每日HackerOne漏洞推送"
		}
	}
	headers = {'Content-Type': 'application/json'}
	req = requests.post(api_url, data=json.dumps(data), headers=headers, timeout=5)
	print(req.text)

# 创建md5对象
def nmd5(str):
    m = hashlib.md5()
    b = str.encode(encoding='utf-8')
    m.update(b)
    str_md5 = m.hexdigest()
    return str_md5

# 有道翻译
# Copy by https://github.com/yhy0/github-cve-monitor/blob/master/github_cve_monitor.py#L345
def translate(word):
    headerstr = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
    bv = nmd5(headerstr)
    lts = str(round(time.time() * 1000))
    salt = lts + '90'
    # 如果翻译失败，{'errorCode': 50}  请查看 fanyi.min.js: https://shared.ydstatic.com/fanyi/newweb/v1.1.7/scripts/newweb/fanyi.min.js
    # 搜索 fanyideskweb   sign: n.md5("fanyideskweb" + e + i + "Y2FYu%TNSbMCxc3t2u^XT")  ，Y2FYu%TNSbMCxc3t2u^XT是否改变，替换即可
    strexample = 'fanyideskweb' + word + salt + 'Y2FYu%TNSbMCxc3t2u^XT'
    sign = nmd5(strexample)
    data = {
        'i': word,
        'from': 'AUTO',
        'to': 'AUTO',
        'smartresult': 'dict',
        'client': 'fanyideskweb',
        'salt': salt,
        'sign': sign,
        'lts': lts,
        'bv': bv,
        'doctype': 'json',
        'version': '2.1',
        'keyfrom': 'fanyi.web',
        'action': 'FY_BY_CLICKBUTTION',
    }
    url = 'http://fanyi.youdao.com/translate_o?smartresult=dict&smartresult=rule'
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
        'Referer': 'http://fanyi.youdao.com/',
        'Origin': 'http://fanyi.youdao.com',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'keep-alive',
        'Host': 'fanyi.youdao.com',
        'cookie': '_ntes_nnid=937f1c788f1e087cf91d616319dc536a,1564395185984; OUTFOX_SEARCH_USER_ID_NCOO=; OUTFOX_SEARCH_USER_ID=-10218418@11.136.67.24; JSESSIONID=; ___rl__test__cookies=1'
    }
    res = requests.post(url=url, data=data, headers=header)
    result_dict = res.json()
    result = ""
    for json_str in result_dict['translateResult'][0]:
        tgt = json_str['tgt']
        result += tgt
    return result


if __name__ == '__main__':
	get_info()
