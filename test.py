# encoding: utf-8
# 
import requests
import urlparse
import string
import codecs
import threading
import sys
from lxml import etree
reload(sys)
sys.setdefaultencoding('utf-8')
# 禁用安全请求警告
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


import time
import threadPool 
from MySqlConn import Mysql 


def get_cookie(cookie):
	cookies={}
	for line in cookie.split(';'):
		name,value = line.split('=')
		cookies[name]=value
	return cookies

def request(url,cookie=""):
	try:
		req = requests.session()
		if cookie.strip() != "":
			cookie = get_cookie(cookie)
		headers = {

			'Connection':'close',
			'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36',
			'cept-Language':'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
			'Accept':'*/*',
			'Referer':url,
		}
		req.keep_alive = False
		req.adapters.DEFAULT_RETRIES = 2
		html = req.get(url,headers=headers,cookies=cookie,allow_redirects=True,verify=False,timeout=6)
		return html.text
	except Exception, e:
		print e
		return None


class VulInfo:


	def __init__(self,vul_id,vul_cve,vul_name,vul_desc,vul_soul,vul_data):
		self.id = ""
		self.vul_id = vul_id
		self.vul_cve = vul_cve
		self.vul_name = vul_name
		self.vul_desc = vul_desc
		self.vul_soul = vul_soul
		self.vul_data = vul_data

	def tostr(self):
		return str(self.vul_id)+"\t"+self.vul_cve+"\t"+self.vul_name

def Getinfo(html,vid):

	try:
		vul_id = vid
		root = etree.HTML(html)
		links = root.xpath("/html/body/div[1]/div/div/table/tr[1]/td/text()")
		vul_name = links[0] #漏洞名字
		links = root.xpath("/html/body/div[1]/div/div/table/tr[2]/td/text()")
		vul_desc = links[0]
		links = root.xpath("/html/body/div[1]/div/div/table/tr[3]/td/text()")
		vul_soul = links[0]
		links = root.xpath("/html/body/div[1]/div/div/table/tr[6]/td/text()")
		vul_data = links[0] #插件日期
		links = root.xpath("/html/body/div[1]/div/div/table/tr[7]/td/text()")
		vul_cve = links[0] #插件cve
		if vul_cve.strip().startswith("CVE"):
			vulInfo = VulInfo(vul_id,vul_cve.strip(),vul_name.strip(),vul_desc.strip(),vul_soul.strip().strip(),vul_data.strip())
			return vulInfo
	except Exception, e:
		Writefile("errlog.txt",vid+"\t"+str(e)+"\n")
		print  e




def InsertVul(request, VulInfo):
	if VulInfo != None:
		mysql = Mysql()
		try:
			sql = "INSERT INTO `vulinfo`.`nsfocusvul`  VALUES (NULL, %s, %s, %s, %s, %s, %s)" 
			param = (VulInfo.vul_id,VulInfo.vul_cve,VulInfo.vul_name,VulInfo.vul_desc,VulInfo.vul_soul,VulInfo.vul_data)
			print str(param)+"----- insert-ok"
			mysql.insertOne(sql,param)
			mysql.end()
		except Exception, e:
			Writefile("mysqllog.txt",str(e)+VulInfo.tostr()+"\n")
			print   e
		mysql.dispose()



def Writefile(file,content):
	f=codecs.open(file,'a','utf-8')
	f.write(content)
	f.flush()  
	f.close()


def Test(x):
	time.sleep(2)
	the_page = request("https://222.196.90.11/template/show_vul_desc?id="+str(x),"sessionid=e4f006520b398b11d163c3a5cffa9396")
	print "start ........ "+str(x)
	if the_page != None:
		vulInfo1 = Getinfo(the_page,str(x))
		print vulInfo1
		return vulInfo1


if __name__ == "__main__":

	list1 =[x for x in range(300000,390265)]
	start_time = time.time()
	pool = threadPool.ThreadPool(5) 
	requestss = threadPool.makeRequests(Test, list1,InsertVul) 
	[pool.putRequest(req) for req in requestss] 
	pool.wait() 
	print '%d second use'% (time.time()-start_time)
	


'''
	the_page = request("http://localhost/main.html","").decode("gbk", "ignore");
	vulInfo1 = Getinfo(the_page,"10010")
	mysql = Mysql()
	print mysql
	print vulInfo1.vul_id
	InsertVul(mysql,vulInfo1)
	'''

'''
	for x in xrange(69099,76321):
		the_page = request("https://133.96.90.11/template/show_vul_desc?id="+str(x),"left_menustatue_NSFOCUSRSAS=3|0|https://133.96.90.11/template/index/; csrftoken=xFfTF0x8o6EFCkujHAQuwB3bMdR6JZCV; sessionid=8af1de4251d84a2990a2130cec896b22")
		vulInfo1 = Getinfo(the_page,str(x))
		if vulInfo1 != "":
			string1 =  str(x) +"\t"+vulInfo1.vul_cve + "\t" +vulInfo1.vul_name
			print string1
			str1 = '"%s","%s","%s","%s","%s","%s"+\n' % (str(x), vulInfo1.vul_cve,vulInfo1.vul_data,vulInfo1.vul_name,vulInfo1.vul_desc,vulInfo1.vul_soul)
			Writefile("aa.csv",str1)

str1 = "%s","%s","%s","%s","%s","%s\n" % (str(x),vulInfo1.vul_cve,vulInfo1.vul_name,vulInfo1.vul_desc,vulInfo1.vul_soul,vulInfo1.vul_data)
	the_page = request("https://133.96.90.11/template/show_vul_desc?id=76321","left_menustatue_NSFOCUSRSAS=3|0|https://133.96.90.11/template/index/; csrftoken=xFfTF0x8o6EFCkujHAQuwB3bMdR6JZCV; sessionid=8af1de4251d84a2990a2130cec896b22")
	root = etree.HTML(the_page)
	links = root.xpath("/html/body/div[1]/div/div/table/tr[1]/td/text()")
	print "漏洞名称  "+links[0]
	links = root.xpath("/html/body/div[1]/div/div/table/tr[2]/td/text()")
	print "漏洞描述  "+links[0]
	links = root.xpath("/html/body/div[1]/div/div/table/tr[3]/td/text()")
	print "解决方法  "+links[0]
	links = root.xpath("/html/body/div[1]/div/div/table/tr[6]/td/text()")
	print links[0] #插件日期
	links = root.xpath("/html/body/div[1]/div/div/table/tr[7]/td/text()")
	print "cve " +links[0] #插件日期
	print "ok"
'''