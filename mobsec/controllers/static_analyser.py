import glob
import logging
import subprocess
import base64
import io,re,os,glob,hashlib, zipfile, subprocess,ntpath,shutil,platform,ast,sys
from log import logger
from settings import BASE_DIR, UPLOADS


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
        directory=settings.BASE_DIR   #BASE DIR
        hash_name=request.args['apk']  #MD5
        file_name = base64.b64decode(hash_name)
        #type=request.GET['type'] #APK or SOURCE
        m=re.match('[0-9a-f]{32}',hash_name)
        if m:
            app_dir=os.path.join(directory,'uploads/'+file_name+'.apk'+'/') #APP DIRECTORY
            manifest_data=ReadManifest(app_dir)
            return manifest_data
    except Exception as e:
        print "[ERROR] Viewing AndroidManifest.xml - " + str(e)
        return

def read_manifest(app_dir):
    dat=''
    print "[INFO] Getting Manifest from Source"
    '''if type=="eclipse":
        manifest=os.path.join(app_dir,"AndroidManifest.xml")
    elif _type=="studio":
        manifest=os.path.join(app_dir,"app/src/main/AndroidManifest.xml")'''
    with io.open(manifest,mode='r',encoding="utf8",errors="ignore") as f:
        dat=f.read()

    return dat

def GetManifest(APP_DIR):
    dat=''
    mfest=''
    dat=ReadManifest(APP_DIR).replace("\n","")
    try:
        print "[INFO] Parsing AndroidManifest.xml"
        mfest=minidom.parseString(dat)
    except Exception as e:
        print "[ERROR] Parsing AndroidManifest.xml - " + str(e)
        mfest=minidom.parseString(r'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="Failed"  android:versionName="Failed" package="Failed"  platformBuildVersionCode="Failed" platformBuildVersionName="Failed XML Parsing" ></manifest>')
        print "[WARNING] Using Fake XML to continue the Analysis"
    return mfest

def FileSize(app_path):
	return round(float(os.path.getsize(app_path)) / (1024 * 1024),2)

def HashGen(app_path):
    print "[INFO] Generating Hashes"
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    BLOCKSIZE = 65536
    with io.open(app_path, mode='rb') as app_file:
        buf_block = app_file.read(BLOCKSIZE)
        while len(buf_block) > 0:
            sha1.update(buf_block)
            sha256.update(buf_block)
            buf_block = app_file.read(BLOCKSIZE)
    sha1_val = sha1.hexdigest()
    sha256_val=sha256.hexdigest()
    return sha1_val, sha256_val

def Unzip(app_path, extrac_path):
    print "[INFO] Unzipping"
    try:
        files=[]
        with zipfile.ZipFile(app_path, "r") as z:
                z.extractall(extrac_path)
                files=z.namelist()
        return files
    except Exception as e:
        print "\n[ERROR] Unzipping Error - "+str(e)
        if platform.system()=="Windows":
            print "\n[INFO] Not yet Implemented."
        else:
            print "\n[INFO] Using the Default OS Unzip Utility."
            try:
                subprocess.Popen(['unzip', '-o', '-q', app_path, '-d', extrac_path])
                dat=subprocess.check_output(['unzip','-qq','-l',app_path])
                dat=dat.split('\n')
                x=['Length   Date   Time   Name']
                x=x+dat
                return x
            except Exception as e1:
                print "\n[ERROR] Unzipping Error - "+str(e1)
