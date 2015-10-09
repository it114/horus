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
from settings import BASE_DIR, UPLOADS, TOOLS_DIR


def decompile(name):
    # search through the uploads folder
	file = glob.glob(os.path.join(UPLOADS, name+'.apk')[0]
    fire_jadx = subprocess.Popen(["jadx", "-d", "out", name, file], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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
        app_dir = os.path.join(settings.UPLOADS, file_name+'.apk') #APP DIRECTORY
        manifest_data = read_manifest(app_dir)
        return manifest_data
    except Exception as e:
        logger.error("[*]Viewing AndroidManifest.xml - " + str(e))
        return

def read_manifest(app_dir):
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
        print "[ERROR] Parsing AndroidManifest.xml - " + str(e)
        mfest=minidom.parseString(r'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="Failed"  android:versionName="Failed" package="Failed"  platformBuildVersionCode="Failed" platformBuildVersionName="Failed XML Parsing" ></manifest>')
        print "[WARNING] Using Fake XML to continue the Analysis"
    return mfest

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
