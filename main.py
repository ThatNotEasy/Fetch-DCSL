import base64
import json
import os
import sys
import time
import requests
import argparse
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
from loguru import logger

from modules.widevine_pb2 import SignedDeviceCertificateStatusList

def check(err):
    if err:
        logger.error(err)
        raise Exception(err)

def todays_dcsl_file_name():
    return f"{time.strftime('%Y%m%d')}-dcsl.bin"

class DcslResponse:
    def __init__(self, list_response_header, signed_list):
        self.listResponseHeader = list_response_header
        self.signedList = signed_list

def fetch_dcsl_data():
    key = ""  # INPUT UR KEY
    url = f"https://www.googleapis.com/certificateprovisioning/v1/devicecertificatestatus/list?key={key}"
    
    logger.debug(f"Sending POST request to {url}")
    response = requests.post(url, headers={"Content-Type": "application/x-www-form-urlencoded"})
    logger.debug(f"Request headers: {response.request.headers}")
    logger.debug(f"Request body: {response.request.body}")
    logger.debug(f"Response status code: {response.status_code}")
    logger.debug(f"Response headers: {response.headers}")
    logger.debug(f"Response body: {response.text}")
    
    check(response.raise_for_status())

    dcsl_response_body = DcslResponse(**response.json())
    signed_list = dcsl_response_body.signedList

    if not signed_list:
        logger.error('no "signedList" element in JSON response')
        raise ValueError('no "signedList" element in JSON response')

    decoded = base64.urlsafe_b64decode(signed_list)
    
    with open(todays_dcsl_file_name(), 'wb') as f:
        f.write(decoded)
    
    return decoded

def read_dcsl_data(file):
    with open(file, 'rb') as f:
        return f.read()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--fetch', action='store_true', help='fetch fresh DCSL')
    parser.add_argument('-s', '--system-id', type=int, help='report on specific system ID')
    parser.add_argument('-m', '--list-manufacturers', action='store_true', help='list all manufacturers as CSV')
    args = parser.parse_args()

    try:
        if os.path.exists(todays_dcsl_file_name()):
            logger.debug(f"Reading data from {todays_dcsl_file_name()}")
            data = read_dcsl_data(todays_dcsl_file_name())
        elif args.fetch:
            logger.debug("Fetching fresh DCSL data")
            data = fetch_dcsl_data()
        else:
            logger.debug("Reading data from stdin")
            data = sys.stdin.buffer.read()
    except Exception as e:
        logger.error(f"Error reading data: {e}")
        sys.exit(1)

    sdcsl = SignedDeviceCertificateStatusList()
    try:
        sdcsl.ParseFromString(data)
    except DecodeError as e:
        logger.error(f"Failed to parse protocol buffer: {e}")
        sys.exit(1)

    if args.system_id:
        dcs_array = sdcsl.certificate_status_list.certificate_status
        found = False
        for dcs in dcs_array:
            if dcs.device_info.system_id == args.system_id:
                found = True
                json_output = MessageToJson(dcs)
                logger.debug(f"System ID {args.system_id} found: {json_output}")
                print(json_output)
                return
        if not found:
            error_message = f"Can't find device certificate entry with system ID {args.system_id}"
            logger.error(error_message)
            print(error_message)
            sys.exit(1)
        return

    if args.list_manufacturers:
        dcs_array = sdcsl.certificate_status_list.certificate_status
        manufacturers = {}
        for dcs in dcs_array:
            manufacturer = dcs.device_info.manufacturer
            if manufacturer:
                if manufacturer in manufacturers:
                    manufacturers[manufacturer] += 1
                else:
                    manufacturers[manufacturer] = 1
        for manufacturer, device_count in manufacturers.items():
            logger.debug(f"Manufacturer: {manufacturer}, Device Count: {device_count}")
            print(f"{manufacturer}, {device_count}")
        return

    json_output = MessageToJson(sdcsl)
    logger.debug(f"Full JSON output: {json_output}")
    print(json_output)
    return

if __name__ == "__main__":
    logger.add(sys.stderr, level="DEBUG")
    main()
