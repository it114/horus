import glob
import logging
import subprocess
import base64
import io
import re
import os
import hashlib
import zipfile
import ntpath
import shutil
import platform
import ast
import sys
from xml.dom import minidom
from log import logger
from settings import BASE_DIR, UPLOADS_DIR, TOOLS_DIR, OUTPUT_DIR
from utils import get_file_paths


def decompile(name):
    # search through the uploads folder
	file = glob.glob(os.path.join(UPLOADS, name+'.apk')[0]
    fire_jadx = subprocess.Popen(["jadx", "-d", "out", os.path.join(OUTPUT_DIR, name), file], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # set to communicate with the logger
    stdout, stderr = fire_jadx.communicate()
    if stdout:
        logger.info(stdout)
    if stderr:
        logger.error(stderr)

def manifest_view(request):
    try:
        hash_name = request.args['apk']  #b64
        file_name = base64.b64decode(hash_name)
        # do not check for the hash just yet (maybe in future)
        app_dir = os.path.join(UPLOADS_DIR, file_name+'.apk') #APP DIRECTORY
        manifest_data = read_manifest(app_dir)
        return manifest_data
    except Exception as e:
        logger.error("[*]Viewing AndroidManifest.xml - " + str(e))
        return

def read_manifest(app_dir):
    """
    - still incomplete
    """
    logger.info("[*]Getting the manifest from decompiled source..")
    manifest = os.path.join(app_dir,"AndroidManifest.xml")
    with io.open(manifest,mode='r',encoding="utf8",errors="ignore") as manifest_file:
        data = manifest_file.read()
    return data

def get_manifest(app_dir)
    manifest = read_manifest(app_dir).replace("\n","")
    try:
        logger.info("[*]Parsing AndroidManifest.xml...")
        parsed_manifest = minidom.parseString(dat)
    except Exception as e:
        logger.error("[*] Parsing AndroidManifest.xml - " + str(e))
        parsed_manifest = minidom.parseString(r'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="Failed"  android:versionName="Failed" package="Failed"  platformBuildVersionCode="Failed" platformBuildVersionName="Failed XML Parsing" ></manifest>')
        logger.warn("[*] Using fake XML to continue the analysis...")
    return parsed_manifest

def size(app_dir):
	return round(float(os.path.getsize(app_dir)) / (1024 * 1024), 2)

def hash_generator(apk_path):
    logger.info("[*] Generating hashes..")
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    # fixed blocksize
    BLOCKSIZE = 65536
    with io.open(apk_path, mode='rb') as app:
        buf_block = app.read(BLOCKSIZE)
        while len(buf_block) > 0:
            sha1.update(buf_block)
            sha256.update(buf_block)
            buf_block = app.read(BLOCKSIZE)
    sha1_val = sha1.hexdigest()
    sha256_val=sha256.hexdigest()
    return {"sha1": sha1_val, "sha256": sha256_val}

def get_cert(app_dir):
    logger.info("[*] Getting hardcoded certificates...")
    files = get_file_paths(app_dir)
    # an empty string
    certs = ''
    for file in files:
        extension = file.split('.')[-1]
        if re.search("cer|pem|cert|crt|pub|key|pfx|p12", extension):
            certs += escape(f) + "</br>"
    if len(certs)>1:
        certs = "<tr><td>Certificate/Key Files Hardcoded inside the App.</td><td>"+certs+"</td><tr>"
    return certz

def str_permissions(permissions):
    logger.info("[*] Formatting permissions...")
    perm_str = ''
    for each in permissions:
        perm_str += '<tr><td>' + each + '</td>'
        for inner in permissions[each]:
            perm_str += '<td>' + inner + '</td>'
        perm_str += '</tr>'
    perm_str = perm_str.replace('dangerous','<span class="label label-danger">dangerous</span>').replace('normal','<span class="label label-info">normal</span>').replace('signatureOrSystem','<span class="label label-warning">SignatureOrSystem</span>').replace('signature','<span class="label label-success">signature</span>')
    return perm_str

def cert_info(app_dir):
    logger.info("[*] Reading signer certificate...")
    cert = os.path.join(app_dir,'META-INF/')
    printer = os.path.join(TOOLS_DIR, 'CertPrint.jar')
    files = [ f for f in os.listdir(cert) if os.path.isfile(os.path.join(cert, f)) ]
    if "CERT.RSA" in files:
        cert_file = os.path.join(cert,"CERT.RSA")
    else:
        for f in files:
            if f.lower().endswith(".rsa"):
                cert_file = os.path.join(cert, f)
            elif f.lower().endswith(".dsa"):
                cert_file = os.path.join(cert, f)

    args = ['java','-jar', printer, cert_file]
    info = escape(subprocess.check_output(args)).replace('\n', '</br>')
    return info

def get_strings(name, app_dir):
    logger.info("[*] Extracting strings from .apk...")
    strings_tool = os.path.join(TOOLS_DIR, 'strings_from_apk.jar')
    args = ['java', '-jar', strings_tool, os.path.join(UPLOADS, name), app_dir]
    subprocess.call(args)
    strings = ''
    try:
        with io.open(app_dir + 'strings.json', mode='r', encoding="utf8", errors="ignore") as file:
            strings += file.read()
    except:
        pass
    strings = strings[1:-1].split(",")
    return strings


