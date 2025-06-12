import MySQLdb
import random
from datetime import datetime, timedelta

# Kết nối database
conn = MySQLdb.connect(
    host="localhost",
    user="snort_user",
    passwd="your_password",  # Đổi thành mật khẩu thật
    db="snort_db"
)
cursor = conn.cursor()

# Thời gian bắt đầu
base_time = datetime.now()

# Danh sách các rule DNP3
dnp3_rules = [
    {
        "sid": 100000,
        "msg": "DNP3 Read Device Attribute - Manufacturer Name (Attr 252)",
        "classification": "Attempted Information Leak",
        "priority": 2
    },
    {
        "sid": 2,
        "msg": "DNP3 Cold Restart Command Issued",
        "classification": "Attempted Denial of Service",
        "priority": 1
    },
    {
        "sid": 5,
        "msg": "DNP3 Disable Unsolicited Messaging Command",
        "classification": "Protocol Command Decode",
        "priority": 2
    },
    {
        "sid": 100001,
        "msg": "DNP3 Read Device Name - User Assigned  (Attr 247)",
        "classification": "Attempted Information Leak",
        "priority": 2
    },
    {
        "sid": 3,
        "msg": "DNP3 Warm Restart Command Issued",
        "classification": "Attempted Denial of Service",
        "priority": 1
    }
]

# IP mẫu
src_ip_pool = [
    "192.168.1.{}".format(i) for i in range(10, 20)
] + [
    "10.10.10.{}".format(i) for i in range(1, 10)
] + [
    "172.16.{}.{}".format(i, j) for i in range(0, 2) for j in range(1, 5)
] + [
    "45.77.88.{}".format(i) for i in range(1, 5)
] + [
    "1.1.1.1", "8.8.8.8", "13.248.118.1"
]

dst_ip_pool = [
    "192.168.100.11", "10.0.0.1", "172.20.10.5", "13.227.3.100", "103.21.244.1"
]

# Tạo dữ liệu giả
for i in range(300):
    ts = base_time - timedelta(minutes=i * 2)
    src_ip = random.choice(src_ip_pool)
    dst_ip = random.choice(dst_ip_pool)
    rule = random.choice(dnp3_rules)
    
    data = (
        ts.strftime("%Y-%m-%d %H:%M:%S"),
        1,  # gid
        rule["sid"],
        1,  # rev
        rule["msg"],
        rule["classification"],
        rule["priority"],
        "TCP",  # DNP3 uses TCP
        src_ip,
        random.randint(1000, 65000),  # src_port
        dst_ip,
        20000  # DNP3 port
    )
    cursor.execute("""
        INSERT INTO events (timestamp, gid, sid, rev, message, classification, priority, protocol, src_ip, src_port, dst_ip, dst_port)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, data)

conn.commit()
cursor.close()
conn.close()
print("✅ Đã thêm 300 dòng dữ liệu giả cho các rule DNP3.")