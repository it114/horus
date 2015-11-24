import urllib
import urllib2
import subprocess
import io
import os
import time
import hashlib
from framework.log import logger
from webapp.settings import UPLOADS_DIR, TOOLS_DIR, OUTPUT_DIR
from webapp.utils import post_multipart

# Adjust PYTHONPATH
import androlyze as anz
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from framework.stadyna_analyser import StadynaAnalyser


class StaticAnalyzer(object):
    def __init__(self, name):
        self.name = name
        out = os.path.join(OUTPUT_DIR, self.name.strip(".apk"))
        # create a dir based on name
        if not os.path.exists(out):
            os.makedirs(out)
        self.app_dir = os.path.join(OUTPUT_DIR, self.name.strip(".apk"))
        self.apk = os.path.join(UPLOADS_DIR, self.name)

    # core method - provides scan as a whole
    def scan(self):
        # draw the graph
        self.genCFG()
        return self.info()

    def cert_info(self):
        logger.info("Unzipping the apk to the app directory...")
        try:
            unzip = subprocess.Popen(["unzip", "-d", self.app_dir, self.apk], stderr=subprocess.STDOUT)
        except Exception as e1:
            logger.error("\n[ERROR] Unzipping Error - "+str(e1))
        logger.info("Reading Signer Certificate")
        cert = os.path.join(self.app_dir, 'META-INF')
        CP_PATH = TOOLS_DIR + '/CertPrint.jar'
        files = os.listdir(cert)
        if "CERT.RSA" in files:
            certfile = os.path.join(cert, "CERT.RSA")
        else:
            for f in files:
                if f.lower().endswith(".rsa"):
                    certfile = os.path.join(cert, f)
                elif f.lower().endswith(".dsa"):
                    certfile = os.path.join(cert, f)

        args = ['java', '-jar', CP_PATH, certfile]
        data = subprocess.check_output(args).replace('\n', '</br>')
        return data

    def info(self):
        a, d, dx = anz.AnalyzeAPK(self.apk, decompiler='dad')
        # logger.warn(a.get_files_types())
        output = {
            "name": self.name,
            "size": self.size(),
            "cert": self.cert_info(),
            "hashes": self.hash_generator(),
            "is_valid": a.is_valid_APK(),
            "package_name": a.get_package(),
            "manifest_analysis": self.manifest_analysis(a.get_android_manifest_xml(), a.get_main_activity()),
            "target_sdk_version": a.get_target_sdk_version(),
            "min_sdk_version": a.get_min_sdk_version(),
            "max_sdk_version": a.get_max_sdk_version(),
            "libraries": a.get_libraries(),
            "detailed_permissions": a.get_details_permissions(),
            "file_types": a.get_files_types(),
            "files": a.get_files(),
            "strings": self.get_strings(),
            "version_name": a.get_androidversion_name(),
            "version_code": a.get_androidversion_code(),
            "permissions": a.permissions,
            "activities": a.get_activities(),
            "services": a.get_services(),
            "providers": a.get_providers(),
            "receivers": a.get_receivers(),
            "main_activity": a.get_main_activity(),
            "misc": self.display_dvm_info()
        }
        return output

    def genCFG(self):
        result = StadynaAnalyser()
        result.makeFileAnalysis(self.apk)
        result.performFinalInfoSave(self.app_dir, self.name)

    def display_dvm_info(self):
        a = apk.APK(self.apk)
        vm = dvm.DalvikVMFormat(a.get_dex())
        vmx = analysis.uVMAnalysis(vm)

        return {"Native": analysis.is_native_code(vmx),
                "Dynamic": analysis.is_dyn_code(vmx),
                "Reflection": analysis.is_reflection_code(vmx),
                "Obfuscation": analysis.is_ascii_obfuscation(vm),
                }

    def manifest_analysis(self, mfxml, mainact):
        logger.info("Manifest Analysis Started")
        manifest = mfxml.getElementsByTagName("manifest")
        services = mfxml.getElementsByTagName("service")
        providers = mfxml.getElementsByTagName("provider")
        receivers = mfxml.getElementsByTagName("receiver")
        applications = mfxml.getElementsByTagName("application")
        datas = mfxml.getElementsByTagName("data")
        intents = mfxml.getElementsByTagName("intent-filter")
        actions = mfxml.getElementsByTagName("action")
        granturipermissions = mfxml.getElementsByTagName("grant-uri-permission")
        for node in manifest:
            package = node.getAttribute("package")
        RET = ''
        EXPORTED = []
        # SERVICES
        # search for services without permissions set
        # if a service is exporeted and has no permission
        # nor an intent filter, flag it
        # I doubt if this part gets executed ever
        for service in services:
            if service.getAttribute("android:exported") == 'true':
                perm = ''
                if service.getAttribute("android:permission"):
                    # service permission exists
                    perm = ' (permission '+service.getAttribute("android:permission")+' exists.) '
                servicename = service.getAttribute("android:name")
                RET = RET + '<tr><td>Service (' + servicename + ') is not Protected.'+perm+' <br>[android:exported=true]</td><td><span class="label label-danger">high</span></td><td> A service was found to be shared with other apps on the device without an intent filter or a permission requirement therefore leaving it accessible to any other application on the device.</td></tr>'

        # APPLICATIONS
        for application in applications:

            if application.getAttribute("android:debuggable") == "true":
                RET = RET + '<tr><td>Debug Enabled For App <br>[android:debuggable=true]</td><td><span class="label label-danger">high</span></td><td>Debugging was enabled on the app which makes it easier for reverse engineers to hook a debugger to it. This allows dumping a stack trace and accessing debugging helper classes.</td></tr>'
            if application.getAttribute("android:allowBackup") == "true":
                RET = RET+ '<tr><td>Application Data can be Backed up<br>[android:allowBackup=true]</td><td><span class="label label-warning">medium</span></td><td>This flag allows anyone to backup your application data via adb. It allows users who have enabled USB debugging to copy application data off of the device.</td></tr>'
            elif application.getAttribute("android:allowBackup") == "false":
                pass
            else:
                RET = RET + '<tr><td>Application Data can be Backed up<br>[android:allowBackup] flag is missing.</td><td><span class="label label-warning">medium</span></td><td>The flag [android:allowBackup] should be set to false. By default it is set to true and allows anyone to backup your application data via adb. It allows users who have enabled USB debugging to copy application data off of the device.</td></tr>'
            if application.getAttribute("android:testOnly") == "true":
                RET = RET + '<tr><td>Application is in Test Mode <br>[android:testOnly=true]</td><td><span class="label label-danger">high</span></td><td> It may expose functionality or data outside of itself that would cause a security hole.</td></tr>'
            for node in application.childNodes:
                ad = ''
                if node.nodeName == 'activity':
                    itmname = 'Activity'
                    ad = 'n'
                elif node.nodeName == 'activity-alias':
                    itmname = 'Activity-Alias'
                    ad = 'n'
                elif node.nodeName == 'provider':
                    itmname = 'Content Provider'
                elif node.nodeName == 'receiver':
                    itmname = 'Broadcast Receiver'
                elif node.nodeName == 'service':
                    itmname = 'Service'
                else:
                    itmname = 'NIL'
                item = ''
                # Task Affinity
                if ((itmname == 'Activity' or itmname == 'Activity-Alias') and (node.getAttribute("android:taskAffinity"))):
                    item = node.getAttribute("android:name")
                    RET = RET + '<tr><td>TaskAffinity is set for Activity </br>('+item + ')</td><td><span class="label label-danger">high</span></td><td>If taskAffinity is set, then other application could read the Intents sent to Activities belonging to another task. Always use the default setting keeping the affinity as the package name in order to prevent sensitive information inside sent or received Intents from being read by another application.</td></tr>'
                # LaunchMode
                if ((itmname == 'Activity' or itmname =='Activity-Alias') and ((node.getAttribute("android:launchMode")=='singleInstance') or (node.getAttribute("android:launchMode")=='singleTask'))):
                    item = node.getAttribute("android:name")
                    RET = RET + '<tr><td>Launch Mode of Activity ('+item + ') is not standard.</td><td><span class="label label-danger">high</span></td><td>An Activity should not be having the launch mode attribute set to "singleTask/singleInstance" as it becomes root Activity and it is possible for other applications to read the contents of the calling Intent. So it is required to use the "standard" launch mode attribute when sensitive information is included in an Intent.</td></tr>'
                # Exported Check
                item = ''
                isExp = False
                if ('NIL' != itmname) and (node.getAttribute("android:exported") == 'true'):
                    isExp = True
                    perm = ''
                    item = node.getAttribute("android:name")
                    if node.getAttribute("android:permission"):
                        # permission exists
                        perm = ' (permission '+node.getAttribute("android:permission")+' exists.) '
                    if item != mainact:
                        if (itmname == 'Activity' or itmname =='Activity-Alias'):
                            EXPORTED.append(item)
                        RET = RET +'<tr><td>'+itmname+' (' + item + ') is not Protected.'+perm+' <br>[android:exported=true]</td><td><span class="label label-danger">high</span></td><td> A'+ad+' '+itmname+' was found to be shared with other apps on the device therefore leaving it accessible to any other application on the device.</td></tr>'
                else:
                    isExp = False
                impE = False
                if ('NIL' != itmname) and (node.getAttribute("android:exported") == 'false'):
                    impE = True
                else:
                    impE = False
                if (isExp == False and impE == False):
                    isInf = False
                    # Logic to support intent-filter
                    intentfilters = node.childNodes
                    for i in intentfilters:
                        inf = i.nodeName
                        if inf == "intent-filter":
                            isInf = True
                    if isInf:
                        item = node.getAttribute("android:name")
                        if item != mainact:
                            if (itmname == 'Activity' or itmname == 'Activity-Alias'):
                                EXPORTED.append(item)
                            RET = RET +'<tr><td>'+itmname+' (' + item + ') is not Protected.<br>An intent-filter exists.</td><td><span class="label label-danger">high</span></td><td> A'+ad+' '+itmname+' was found to be shared with other apps on the device therefore leaving it accessible to any other application on the device. The presence of intent-filter indicates that the '+itmname+' is explicitly exported.</td></tr>'

        ##GRANT-URI-PERMISSIONS
        title = 'Improper Content Provider Permissions'
        desc = ('A content provider permission was set to allows access from any other app on the ' +
                'device. Content providers may contain sensitive information about an app and therefore should not be shared.')
        for granturi in granturipermissions:
            if granturi.getAttribute("android:pathPrefix") == '/':
                RET = RET + '<tr><td>' + title + '<br> [pathPrefix=/] </td>' + '<td><span class="label label-danger">high</span></td><td>'+ desc+'</td></tr>'
            elif granturi.getAttribute("android:path") == '/':
                RET = RET + '<tr><td>' + title + '<br> [path=/] </td>' + '<td><span class="label label-danger">high</span></td><td>'+ desc+'</td></tr>'
            elif granturi.getAttribute("android:pathPattern") == '*':
                RET = RET + '<tr><td>' + title + '<br> [path=*]</td>' + '<td><span class="label label-danger">high</span></td><td>'+ desc +'</td></tr>'

        ##DATA
        for data in datas:
            if data.getAttribute("android:scheme") == "android_secret_code":
                xmlhost = data.getAttribute("android:host")
                desc = ("A secret code was found in the manifest. These codes, when entered into the dialer " +
                    "grant access to hidden content that may contain sensitive information.")
                RET = RET +  '<tr><td>Dailer Code: '+ xmlhost + 'Found <br>[android:scheme="android_secret_code"]</td><td><span class="label label-danger">high</span></td><td>'+ desc + '</td></tr>'
            elif data.getAttribute("android:port"):
                dataport = data.getAttribute("android:port")
                title = "Data SMS Receiver Set"
                desc = "A binary SMS recevier is configured to listen on a port. Binary SMS messages sent to a device are processed by the application in whichever way the developer choses. The data in this SMS should be properly validated by the application. Furthermore, the application should assume that the SMS being received is from an untrusted source."
                RET = RET +  '<tr><td> on Port: ' + dataport +  'Found<br>[android:port]</td><td><span class="label label-danger">high</span></td><td>'+ desc +'</td></tr>'

        ##INTENTS

        for intent in intents:
            if intent.getAttribute("android:priority").isdigit():
                value = intent.getAttribute("android:priority")
                if int(value) > 100:
                    RET = RET + '<tr><td>High Intent Priority ('+ value +')<br>[android:priority]</td><td><span class="label label-warning">medium</span></td><td>By setting an intent priority higher than another intent, the app effectively overrides other requests.</td></tr>'
        ##ACTIONS
        for action in actions:
            if action.getAttribute("android:priority").isdigit():
                value = action.getAttribute("android:priority")
                if int(value) > 100:
                    RET = RET + '<tr><td>High Action Priority (' + value+')<br>[android:priority]</td><td><span class="label label-warning">medium</span></td><td>By setting an action priority higher than another action, the app effectively overrides other requests.</td></tr>'
        if len(RET) < 2:
            RET = '<tr><td>None</td><td>None</td><td>None</td><tr>'
        return RET

    def get_strings(self):
        logger.info("Extracting Strings from APK")
        strings_tool = TOOLS_DIR + '/strings_from_apk.jar'
        args = ['java', '-jar', strings_tool, self.apk, self.app_dir]
        subprocess.call(args)
        data = ''
        try:
            with io.open(self.app_dir + 'strings.json', mode='r', encoding="utf8", errors="ignore") as f:
                data = f.read()
        except:
            pass
        data = data[1:-1].split(",")
        return data

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
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        # fixed blocksize
        BLOCKSIZE = 65536
        with io.open(self.apk, mode='rb') as app:
            buf_block = app.read(BLOCKSIZE)
            while len(buf_block) > 0:
                md5.update(buf_block)
                sha1.update(buf_block)
                sha256.update(buf_block)
                buf_block = app.read(BLOCKSIZE)
        md5_val = md5.hexdigest()
        sha1_val = sha1.hexdigest()
        sha256_val = sha256.hexdigest()
        return {"md5": md5_val, "sha1": sha1_val, "sha256": sha256_val}

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
