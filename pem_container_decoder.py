#!/usr/bin/python3

import re
import sys
import time
import socket
import struct
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

path = sys.argv[1]
host = sys.argv[2]
port = sys.argv[3]
mode = "exists"


def zabbix_get(host, path, mode, port):
    key = f"vfs.file.{mode}[{path}]"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        address = socket.gethostbyaddr(str(host))
        ip = address[2]
        dns = address[0]
        try:
            sock.connect((str(host), int(port)))
            header_field = struct.pack("<4sBQ", "ZBXD".encode("UTF-8"), 1, len(key))
            data = header_field + key.encode("UTF-8")
            sock.sendall(data)

            data = "".encode("UTF-8")
            while True:
                buff = sock.recv(1024)
                if not buff:
                    break
                data += buff

            response = data
            header, version, length = struct.unpack("<4sBQ", response[:13])
            try:
                (data,) = struct.unpack("<%ds" % length, response[13:13 + length])
                sock.close()
                response_data = str(data.decode("UTF-8"))
                response_data = response_data.encode("UTF-8")
                return response_data
            except struct.error:
                if mode == "exists":
                    response = re.sub(r"ZBXD.*?(?=\d+)", "", str(response.decode("UTF-8", "ignore")))
                elif mode == "contents":
                    response = re.sub(r"ZBXD.*?(?=-----BEGIN CERTIFICATE-----)", "", str(response.decode("UTF-8", "ignore")))
                response_data = str(response)
                response_data = response_data.encode("UTF-8")
                return response_data

        except socket.timeout:
            print(f'Timeout! DNS: {dns}, ("{ip}")')
        except TimeoutError:
            print(f'Timeout! DNS: {dns}, ("{ip}")')
        except ConnectionRefusedError:
            print(f'Connection Refused! DNS: {dns}, ("{ip}")')
        except ConnectionResetError:
            print(f'Connection Reset! DNS: {dns}, ("{ip}")')
        except socket.herror:
            print(f'No PTR record! DNS: {dns}, ("{ip}")')
    except Exception as error:
        print(str(error))
        response_data = bytes("2".encode("UTF-8"))
        return response_data


def get_cert(pem_data):
    try:
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        not_after = cert.not_valid_after
        timestamp_after = time.mktime(datetime.datetime.strptime(str(not_after), "%Y-%m-%d %H:%M:%S").timetuple())
        timestamp_now = time.time()
        timestamp_diff = (int(timestamp_after) - int(timestamp_now))
        days_left = (timestamp_diff / 86400)
        print(int(days_left))
    except Exception:
        error = re.sub(r"^.*ZBX_NOTSUPPORTED.*?(?=\w)", "", str(pem_data.decode("UTF-8", "ignore")))
        print("Decode file error! " + str(error))

check_file_exist = zabbix_get(host, path, mode, port)

if check_file_exist.decode("UTF-8") == "1":
    mode = "contents"
    pem_data = zabbix_get(host, path, mode, port)
    get_cert(pem_data)
elif check_file_exist.decode("UTF-8") == "2":
    print("An unexpected problem occurred!")
else:
    print("Certificate file not found!")

