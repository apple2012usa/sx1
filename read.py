 import requests
 ​
 r = requests.get('https://www.baidu.com')
 r.encoding = 'utf8'
 print(r.status_code)
 print(r.text[:17])
 input('pause')
