import urllib
import urllib2
from urllib2 import urlopen, HTTPError
import subprocess
import io
import os
import time
import hashlib
from framework.log import logger
from webapp.settings import UPLOADS_DIR, TOOLS_DIR, OUTPUT_DIR

# Adjust PYTHONPATH
import androlyze as anz
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.core.analysis import analysis
from androguard.core.bytecodes.apk import *

# Androwarn modules import
from framework.core import *
from framework.api_constants import *
from framework.util import *
from framework.api import *

from framework.malicious_behaviours.Audio_video_interception import *
from framework.malicious_behaviours.code_execution import *
from framework.malicious_behaviours.connection_interfaces import *
from framework.malicious_behaviours.device_settings import *
from framework.malicious_behaviours.Geolocation_information import *
from framework.malicious_behaviours.PIM_leakage import *
from framework.malicious_behaviours.remote_connection import *
from framework.malicious_behaviours.telephony_identifiers import *
from framework.malicious_behaviours.telephony_services import *


class StaticAnalyzer(object):
    def __init__(self, name):
        self.name = name
        self.app_dir = os.path.join(OUTPUT_DIR, self.name.strip(".apk"))
        self.apk = os.path.join(UPLOADS_DIR, self.name)
        self.extract_dir = os.path.join(self.app_dir, "extracted")
        self.decompile_dir = os.path.join(self.app_dir, "decompiled")
        if not os.path.exists(self.app_dir):
            os.makedirs(self.app_dir)

    def init(self):
        # step 1:Extract
        logger.debug("Unzipping the APK")
        self.unzip()
        self.decompile()
        return {}

    # core method - provides scan as a whole
    def scan(self):
        return self.info()

    def cert_info(self):
        logger.info("Extracting certificate...")
        certdir = os.path.join(self.extract_dir, 'META-INF')
        if "CERT.RSA" in os.listdir(certdir):
            certfile = os.path.join(certdir, "CERT.RSA")
        else:
            for file in os.listdir(certdir):
                if file.lower().endswith(".rsa"):
                    certfile = os.path.join(certdir, file)
                    break
                elif file.lower().endswith(".dsa"):
                    certfile = os.path.join(certdir, file)
                else:
                    certfile = ''
        data = subprocess.Popen('openssl pkcs7 -inform DER -noout -print_certs -text -in %s' % certfile,
                                shell=True,
                                stdout=subprocess.PIPE).communicate()[0]
        return data.replace('\n', '<br>')

    def info(self):
        a, d, dx = anz.AnalyzeAPK(self.apk, decompiler='dad')
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
            "detailed_permissions": a.get_details_permissions(),
            "file_types": a.get_files_types(),
            "files": a.get_files(),
            "strings": d.get_strings(),
            "classes": d.get_classes_names(),
            "urls": d.get_regex_strings(ur'((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%\'{}-]+)'),
            "emails": d.get_regex_strings("[\w.-]+@[\w-]+\.[\w.]+"),
            "logging": d.get_regex_strings('d_sqlite|d_con_private|log'),
            "version_name": a.get_androidversion_name(),
            "version_code": a.get_androidversion_code(),
            "activities": a.get_activities(),
            "telephony_identifiers_leakage": gather_telephony_identifiers_leakage(dx),
            "device_settings_harvesting": gather_device_settings_harvesting(dx),
            "location_lookup": gather_location_lookup(dx),
            "connection_interfaces_exfiltration": gather_connection_interfaces_exfiltration(dx),
            "telephony_services_abuse": gather_telephony_services_abuse(a, dx),
            "audio_video_eavesdropping": gather_audio_video_eavesdropping(dx),
            "suspicious_connection_establishment": gather_suspicious_connection_establishment(dx),
            "PIM_data_leakage": gather_PIM_data_leakage(dx),
            "code_execution": gather_code_execution(dx),
            "apis_used": self.get_apis_used(dx),
            "services": a.get_services(),
            "providers": a.get_providers(),
            "receivers": a.get_receivers(),
            "main_activity": a.get_main_activity(),
            "misc": self.display_dvm_info()
        }
        return output

    def get_apis_used(self, x):
        return {
                    'classes_list': grab_classes_list(x) ,
                    'internal_classes_list': grab_internal_classes_list(x),
                    'external_classes_list': grab_external_classes_list(x),
                    'internal_packages_list': grab_internal_packages_list(x),
                    'external_packages_list': grab_external_packages_list(x),
                    'intents_sent': grab_intents_sent(x)
                }


    def display_dvm_info(self):
        a = apk.APK(self.apk)
        vm = dvm.DalvikVMFormat(a.get_dex())
        vmx = analysis.uVMAnalysis(vm)

        return {
                    "Native": analysis.is_native_code(vmx),
                    "Dynamic": analysis.is_dyn_code(vmx),
                    "Reflection": analysis.is_reflection_code(vmx),
                    "Obfuscation": analysis.is_ascii_obfuscation(vm)
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

    def decompile(self):
        jadx = os.path.join(TOOLS_DIR, 'jadx/bin/jadx')
        args = [jadx, "-d", self.decompile_dir, self.apk]
        fire_jadx = subprocess.Popen(args, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
        # set to communicate with the logger
        stdout, stderr = fire_jadx.communicate()
        if stdout:
            logger.info(stdout)
        return True
        if stderr:
            logger.error(stderr)
        return False

    def unzip(self):
        os.system('unzip -d %s %s' % (self.extract_dir, self.apk))

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

    """
    def virustotal_check(self):
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
    """

    def grab_application_name_description_icon(self, package_name) :
        """
            @param package_name : package name

            @rtype : (name, description, icon) string tuple
        """

        # Constants
        REQUEST_TIMEOUT = 4
        ERROR_APP_DESC_NOT_FOUND = 'N/A'


        try :
            # Content in English
            url = "http://play.google.com/store/apps/details?id=%s&hl=en" % str(package_name)

            req = urllib2.Request(url)
            response = urllib2.urlopen(req, timeout=REQUEST_TIMEOUT)
            the_page = response.read()

            p_name = re.compile(ur'''<h1 class="doc-banner-title">(.*)</h1>''')
            p_desc = re.compile(ur'''(?:\<div id=\"doc-original-text\" \>)(.*)(?:\<\/div\>\<\/div\>\<div class\=\"doc-description-overflow\"\>)''')
            p_icon = re.compile(ur'''(?:\<div class\=\"doc-banner-icon\"\>)(.*)(?:\<\/div\>\<\/td\><td class="doc-details-ratings-price")''')

            if p_name.findall(the_page) and p_desc.findall(the_page) and p_icon.findall(the_page) :
                name = strip_HTML_tags(p_name.findall(the_page)[0].decode("utf-8"))
                desc = strip_HTML_tags(p_desc.findall(the_page)[0].decode("utf-8"))
                icon_link = p_icon.findall(the_page)[0]

                return (name, desc, icon_link)

            else :
                logger.warn("'%s' application's description and icon could not be found in the page" % str(package_name))
                return ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND

        except HTTPError :
            logger.warn("'%s' application name does not exist on Google Play" % str(package_name))
            return ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND
