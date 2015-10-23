import urllib
import urllib2
import subprocess
import io
import os
import time
import hashlib
from mobsec.log import logger
from mobsec.settings import UPLOADS_DIR, TOOLS_DIR, OUTPUT_DIR
from mobsec.utils import post_multipart

# Adjust PYTHONPATH
import androlyze as anz
from mobsec.controllers.stadyna_analyser import StadynaAnalyser


class StaticAnalyzer(object):
    def __init__(self, name):
        self.name = name
        # create a dir based on name
        if not os.path.exists(os.path.join(OUTPUT_DIR, self.name.strip(".apk"))):
            os.makedirs(os.path.join(OUTPUT_DIR, self.name.strip(".apk")))

        self.app_dir = os.path.join(OUTPUT_DIR, self.name.strip(".apk"))
        self.apk = os.path.join(UPLOADS_DIR, self.name)

    def info(self):
        a, d, dx = anz.AnalyzeAPK(self.apk, decompiler='dex2jar')
        output = {
            "is_valid": a.is_valid_APK(),
            "package_name": a.get_package(),
            "target_sdk_version": a.get_target_sdk_version(),
            "min_sdk_version": a.get_min_sdk_version(),
            "max_sdk_version": a.get_max_sdk_version(),
            "libraries": a.get_libraries(),
            "detailed_permissions": a.get_details_permissions(),
            "file_types": a.get_files_types(),
            "files": a.get_files(),
            "version_name": a.get_androidversion_name(),
            "version_code": a.get_androidversion_code(),
            "permissions": a.permissions,
            "activities": a.get_activities(),
            "services": a.get_services(),
            "providers": a.get_providers(),
            "receivers": a.get_receivers(),
            "main_activity": a.get_main_activity(),
            "strings": d.get_strings()
        }

        return output

    def genCFG(self):
        result = StadynaAnalyser()
        result.makeFileAnalysis(self.apk)
        result.performFinalInfoSave(self.app_dir, self.name)

    def decompile(self):
        # search through the uploads folder
        jadx = os.path.join(TOOLS_DIR, 'jadx/bin/jadx')
        args = [jadx, "-d", self.app_dir, self.apk]
        fire_jadx = subprocess.Popen(args, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
        # set to communicate with the logger
        stdout, stderr = fire_jadx.communicate()
        if stdout:
            logger.info(stdout)
        if stderr:
            logger.error(stderr)

    def size(self):
        return round(float(os.path.getsize(self.apk)) / (1024 * 1024), 2)

    def hash_generator(self):
        logger.info("[*] Generating hashes..")
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        # fixed blocksize
        BLOCKSIZE = 65536
        with io.open(self.apk, mode='rb') as app:
            buf_block = app.read(BLOCKSIZE)
            while len(buf_block) > 0:
                sha1.update(buf_block)
                sha256.update(buf_block)
                buf_block = app.read(BLOCKSIZE)
        sha1_val = sha1.hexdigest()
        sha256_val = sha256.hexdigest()
        return {"sha1": sha1_val, "sha256": sha256_val}

    def virustotal_check(self):
        """
        Upload the file to VirusTotal and get the results (via the API)
        :rtype: JSON
        """
        with open(self.apk, 'rb') as data:
            app = data.read()
        host = "www.virustotal.com"
        selector = "https://www.virustotal.com/vtapi/v2/file/scan"
        fields = [("apikey", os.environ("VIRUSTOTAL_API"))]
        files = [("file", "app.txt", app)]
        json = post_multipart(host, selector, fields, files)
        # this will be used for later requests
        time.sleep(30)
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        parameters = {"resource": "json['scan_id']", "apikey": "os.environ('VIRUSTOTAL_API')"}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = json.loads(urllib2.urlopen(req).read())

        return response["scans"]
