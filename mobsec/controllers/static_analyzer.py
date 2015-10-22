import urllib
import urllib2
import subprocess
import io
import re
import os
import time
import hashlib
from html import escape
from xml.dom import minidom
from mobsec.log import logger
from mobsec.settings import UPLOADS_DIR, TOOLS_DIR, OUTPUT_DIR
from mobsec.utils import get_file_paths, post_multipart


class StaticAnalyzer(object):
    def __init__(self, name):
        self.name = name
        # create a dir based on name
        if not os.path.exists(os.path.join(OUTPUT_DIR, self.name.strip(".apk"))):
            os.makedirs(os.path.join(OUTPUT_DIR, self.name.strip(".apk")))

        self.app_dir = os.path.join(OUTPUT_DIR, self.name.strip(".apk"))
        self.apk = os.path.join(UPLOADS_DIR, self.name)

    def decompile(self):
        # search through the uploads folder
        jadx = os.path.join(TOOLS_DIR, 'jadx/bin/jadx')
        args = [jadx, "-d", "out", self.app_dir, self.apk]
        fire_jadx = subprocess.Popen(args, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
        # set to communicate with the logger
        stdout, stderr = fire_jadx.communicate()
        if stdout:
            logger.info(stdout)
        if stderr:
            logger.error(stderr)

    def manifest_view(self):
        try:
            # do not check for the hash just yet (maybe in future)
            manifest_data = self.read_manifest()
            return manifest_data
        except Exception as e:
            logger.error("[*]Viewing AndroidManifest.xml - " + str(e))
            return

    def read_manifest(self):
        logger.info("[*]Getting the manifest from decompiled source..")
        manifest = os.path.join(self.app_dir, "AndroidManifest.xml")
        with io.open(manifest, mode='r', encoding="utf8", errors="ignore") as manifest_file:
            data = manifest_file.read()
        return data

    def get_manifest(self):
        manifest = self.read_manifest().replace("\n", "")
        try:
            logger.info("[*]Parsing AndroidManifest.xml...")
            parsed_manifest = minidom.parseString(manifest)
        except Exception as e:
            logger.error("[*] Parsing AndroidManifest.xml - " + str(e))
            parsed_manifest = minidom.parseString(r'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="Failed"  android:versionName="Failed" package="Failed"  platformBuildVersionCode="Failed" platformBuildVersionName="Failed XML Parsing" ></manifest>')
            logger.warn("[*] Using fake XML to continue the analysis...")
        return parsed_manifest

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

    def get_cert(self):
        logger.info("[*] Getting hardcoded certificates...")
        files = get_file_paths(self.app_dir)
        # an empty string
        certs = ''
        for file in files:
            extension = file.split('.')[-1]
            if re.search("cer|pem|cert|crt|pub|key|pfx|p12", extension):
                certs += escape(file) + "</br>"
        if len(certs) > 1:
            certs = "<tr><td>Certificate/Key Files Hardcoded inside the App.</td><td>" + \
                certs + "</td><tr>"
        return certs

    @staticmethod
    def str_permissions(permissions):
        logger.info("[*] Formatting permissions...")
        perm_str = ''
        for each in permissions:
            perm_str += '<tr><td>' + each + '</td>'
            for inner in permissions[each]:
                perm_str += '<td>' + inner + '</td>'
            perm_str += '</tr>'
        perm_str = perm_str.replace('dangerous', '<span class="label label-danger">dangerous</span>').replace('normal', '<span class="label label-info">normal</span>').replace('signatureOrSystem','<span class="label label-warning">SignatureOrSystem</span>').replace('signature','<span class="label label-success">signature</span>')
        return perm_str

    def cert_info(self):
        logger.info("[*] Reading signer certificate...")
        cert = os.path.join(self.app_dir, 'META-INF/')
        printer = os.path.join(TOOLS_DIR, 'CertPrint.jar')
        files = [f for f in os.listdir(cert) if os.path.isfile(os.path.join(cert, f))]
        if "CERT.RSA" in files:
            cert_file = os.path.join(cert, "CERT.RSA")
        else:
            for f in files:
                if f.lower().endswith(".rsa"):
                    cert_file = os.path.join(cert, f)
                elif f.lower().endswith(".dsa"):
                    cert_file = os.path.join(cert, f)
        args = ['java', '-jar', printer, cert_file]
        info = escape(subprocess.check_output(args)).replace('\n', '</br>')
        return info

    def get_strings(self):
        logger.info("[*] Extracting strings from .apk...")
        strings_tool = os.path.join(TOOLS_DIR, 'strings_from_apk.jar')
        args = ['java', '-jar', strings_tool, self.apk, self.app_dir]
        subprocess.call(args)
        strings = ''
        try:
            with io.open(self.app_dir + 'strings.json', mode='r', encoding="utf8", errors="ignore") as file:
                strings += file.read()
        except:
            pass
        strings = strings[1:-1].split(",")
        return strings

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
