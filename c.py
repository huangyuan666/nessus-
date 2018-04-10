# coding: utf-8

import csv
import xlwt
import string
import os
import sys
import ConfigParser
from MySqlConn import Mysql
from datetime import datetime
from test import VulInfo
reload(sys)
sys.setdefaultencoding('utf-8')



def GetChinese(name):

	try:
		cp = ConfigParser.SafeConfigParser()
		cp.read('chinese.conf')
		name = cp.get('chinese', name.replace("\n"," "))+u''
	except Exception, e:
		print e
	return name

#文件读取
class GetCve(object):
	"""docstring for GetCve"""
	def __init__(self, filename):
		self.filename = filename

	def ReadCve(self):
		Cvecon = []
		csvfile = open(self.filename, 'rb')
		read = csv.reader(csvfile)

		for line in read:
			if "CVE-" in line[1].strip()  or line[3] != "None":
				Cvecon.append(line)
		csvfile.close() 
		return Cvecon

	def Readall(self):
		Cvecon = []
		csvfile = open(self.filename, 'rb')
		read = csv.reader(csvfile)
		return read

	def AllCve(self):
		cevdata = []
		cvecon = self.ReadCve()
		for row in cvecon:
			Cve =  row[1]
			Risk =  row[3]
			Host =  row[4]
			Protocol =  row[5]
			Port =  row[6]
			Name = row[7]
			Description = row[9]
			Solution = row[10]
			Output = row[12]
			nessus = NessusReport(Cve,Risk,Host,Protocol,Port,Name,Description,Solution,Output)
			cevdata.append(nessus)
		return cevdata

	def AllPort(self):
		portdata = []
		portdata1 = []
		portcon = self.Readall()
		for row in portcon:
			Host =  row[4]
			Protocol =  row[5]
			Port =  row[6]
			Output = row[12]
			if Port == "0" or Port == "Port":
				continue
			Service = row[8]

			ob = Host+":"+Port

			if not ob in portdata:
				portdata.append(Host+":"+Port)
				nessusPort = NessusPort(Host,Port,Protocol,Service,Output)
				portdata1.append(nessusPort)
		return portdata1


		
#漏洞相关对象
class NessusReport(object):

	def __init__(self, Cve,Risk,Host,Protocol,Port,Name,Description,Solution,Output):
		self.Cve = Cve
		self.Risk = GetChinese(Risk)
		self.Host = Host
		self.Protocol = Protocol
		self.Port = Port
		self.Name = Name
		self.Description = Description
		self.Solution = Solution
		self.Output = Output

	def tostr(self):
		string = self.Cve +"\t"+self.Risk +"\t"+self.Host +"\t"+self.Protocol+"\t"+self.Port +"\t"+self.Name
		return string


#端口相关对象

class NessusPort(object):
	def __init__(self, Host,Port,Protocol,Service,Output):
		self.Host = Host
		self.Port = Port
		self.Protocol = Protocol
		self.Service = GetChinese(Service)
		self.Output = Output

	def tostr(self):
		string = self.Host +"\t"+self.Port +"\t"+self.Protocol +"\t"+self.Service+"\t"+self.Output
		return string

#写excel
def CreateExcel(cevObjeclist,portobject,filename):
	bb = cevObjeclist
	cc = portobject
	style0 = xlwt.easyxf('font: name Times New Roman, color-index red, bold on',num_format_str='#,##0.00')
	style1 = xlwt.easyxf(num_format_str='D-MMM-YY')
	 
	wb = xlwt.Workbook()
	ws = wb.add_sheet(u'漏洞情况')
	wp = wb.add_sheet(u'端口情况情况')

	wp.write(0,0,u"序号")
	wp.write(0,1,u"主机ip")
	wp.write(0,2,u"开放端口")
	wp.write(0,3,u"端口协议")
	wp.write(0,4,u"端口服务")
	wp.write(0,5,u"探测输出")

	for x in xrange(0,len(cc)):
		wp.write(x+1,0,x+1)
	
	#host
	for x in xrange(0,len(cc)):
		wp.write(x+1,1,cc[x].Host)


	#port
	for x in xrange(0,len(cc)):
		wp.write(x+1,2,cc[x].Port)

	#Protocol
	for x in xrange(0,len(cc)):
		wp.write(x+1,3,cc[x].Protocol)

	#Service
	for x in xrange(0,len(cc)):
		wp.write(x+1,4,cc[x].Service)

	#Output
	for x in xrange(0,len(cc)):
		wp.write(x+1,5,cc[x].Output)

	ws.write(0,0,u"序号")
	ws.write(0,1,u"CVE编号")
	ws.write(0,2,u"主机IP")
	ws.write(0,3,u"风险等级")
	ws.write(0,4,u"协议")
	ws.write(0,5,u"端口")
	ws.write(0,6,u"漏洞名称")
	ws.write(0,7,u"漏洞描述")
	ws.write(0,8,u"整改建议")
	ws.write(0,9,u"探测输出")
	#顺序
	for x in xrange(0,len(bb)):
		ws.write(x+1,0,x+1)
	
	#cve
	for x in xrange(0,len(bb)):
		ws.write(x+1,1,bb[x].Cve)

	#Host
	for x in xrange(0,len(bb)):
		ws.write(x+1,2,bb[x].Host)

	#Risk
	for x in xrange(0,len(bb)):
		ws.write(x+1,3,bb[x].Risk)

	#Protocol
	for x in xrange(0,len(bb)):
		ws.write(x+1,4,bb[x].Protocol)

	#Port
	for x in xrange(0,len(bb)):
		ws.write(x+1,5,bb[x].Port)

	#Name
	for x in xrange(0,len(bb)):
		ws.write(x+1,6,bb[x].Name)

	#Description
	for x in xrange(0,len(bb)):
		ws.write(x+1,7,bb[x].Description)

	#Solution
	for x in xrange(0,len(bb)):
		ws.write(x+1,8,bb[x].Solution)

	#Output
	for x in xrange(0,len(bb)):
		ws.write(x+1,9,bb[x].Output)

	wb.save(filename)



#查询相关
def CVeReturnNsfocus(str1):
	result = []
	cvelist = str1.split("\n");
	mysql = Mysql()
	for cveone in cvelist:
		sql = "SELECT * FROM nsfocusvul where vul_cve = '%s'" % (cveone.strip())
		res = mysql.getOne(sql)
		if res != False:
			resobj = VulInfo(res["vul_id"],res["vul_cve"],u''+res["vul_name"],u''+res["vul_desc"],u''+res["vul_soul"],res["vul_data"])
			result.append(resobj)
	mysql.dispose()

	return result



def ModifyNessus(NessusReport):
	NsfocusList = []
	for OneRowCve in NessusReport:
		getcve =  OneRowCve.Cve
		getCveName = CVeReturnNsfocus(getcve)
		if len(getCveName) > 0:
			lists = CVeReturnNsfocus(getcve)
			OneRowCve.Name =  '\n'.join([x.vul_name for x in lists])
			OneRowCve.Description = '\n'.join([x.vul_desc for x in lists])
			OneRowCve.Solution = '\n'.join([x.vul_soul for x in lists])
			NsfocusList.append(OneRowCve)
		else:
			NsfocusList.append(OneRowCve)
	return NsfocusList




if __name__ == "__main__":

	if len(sys.argv) != 2:
		print "python c.py filename"
		os._exit(1)
	inputfile = sys.argv[1]
	
	if os.path.isfile(inputfile) == False:
		print u"文件不存在"
		os._exit(1)
	aa = GetCve(inputfile)
	dd =  aa.AllPort()
	bb = aa.AllCve()
	cc =  ModifyNessus(bb)
	for x in cc:
		print x.tostr()
	CreateExcel(cc,dd,inputfile+".xls")
'''
	style0 = xlwt.easyxf('font: name Times New Roman, color-index red, bold on',num_format_str='#,##0.00')
	style1 = xlwt.easyxf(num_format_str='D-MMM-YY')

	alignment = xlwt.Alignment() # Create Alignment
	alignment.horz = xlwt.Alignment.HORZ_CENTER # May be: HORZ_GENERAL, HORZ_LEFT, HORZ_CENTER, HORZ_RIGHT, HORZ_FILLED, HORZ_JUSTIFIED, HORZ_CENTER_ACROSS_SEL, HORZ_DISTRIBUTED
	alignment.vert = xlwt.Alignment.VERT_CENTER # May be: VERT_TOP, VERT_CENTER, VERT_BOTTOM, VERT_JUSTIFIED, VERT_DISTRIBUTED
	style = xlwt.XFStyle() # Create Style
	style.alignment = alignment # Add Alignment to Style

	wb = xlwt.Workbook()
	ws = wb.add_sheet('Sheet 1')
	ws
	ws.write(0,0,u"序号",style)
	ws.write(0,1,u"CVE编号")
	ws.write(0,2,u"主机IP")
	ws.write(0,3,u"风险等级")
	ws.write(0,4,u"协议")
	ws.write(0,5,u"端口")
	ws.write(0,6,u"漏洞名称")
	ws.write(0,7,u"漏洞描述")
	ws.write(0,8,u"整改建议")
	ws.write(0,9,u"探测输出")
	#顺序
	for x in xrange(0,len(bb)):
		ws.write(x+1,0,x+1)
	
	#cve
	for x in xrange(0,len(bb)):
		ws.write(x+1,1,bb[x].Cve)

	#Host
	for x in xrange(0,len(bb)):
		ws.write(x+1,2,bb[x].Host)

	#Risk
	for x in xrange(0,len(bb)):
		ws.write(x+1,3,bb[x].Risk)

	#Protocol
	for x in xrange(0,len(bb)):
		ws.write(x+1,4,bb[x].Protocol)

	#Port
	for x in xrange(0,len(bb)):
		ws.write(x+1,5,bb[x].Port)

	#Name
	for x in xrange(0,len(bb)):
		ws.write(x+1,6,bb[x].Name)

	#Description
	for x in xrange(0,len(bb)):
		ws.write(x+1,7,bb[x].Description)

	#Solution
	for x in xrange(0,len(bb)):
		ws.write(x+1,8,bb[x].Solution)

	#Output
	for x in xrange(0,len(bb)):
		ws.write(x+1,9,bb[x].Output)

	wb.save('example1.xls')

	
	style0 = xlwt.easyxf('font: name Times New Roman, color-index red, bold on',num_format_str='#,##0.00')
	style1 = xlwt.easyxf(num_format_str='D-MMM-YY')
	 
	wb = xlwt.Workbook()
	ws = wb.add_sheet('Sheet 1')
	ws.write(0, 0, 1234.56, style0)
	ws.write(1, 0, datetime.now(), style1)
	ws.write(2, 0, 1)
	ws.write(2, 1, 1)
	ws.write(2, 2, xlwt.Formula("A3+B3"))
	 
	wb.save('example.xls')
'''