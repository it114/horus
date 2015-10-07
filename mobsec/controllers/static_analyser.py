import glob
import subprocess
import base64
from templates import settings
from flask import render_template
import io,re,os,glob,hashlib, zipfile, subprocess,ntpath,shutil,platform,ast,sys

def decompileInfo():
	filenames = glob.glob(os.path.join(BASE_DIR,"uploads/*.apk"))
	for file in filenames:
		f_name = file.split('.apk')
		f = open(f_name,'r')
		process = subprocess.Popen(["jadx","-d","out",f_name,file],stderr=f)

def ManifestView(request):
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

def ReadManifest(app_dir):
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

def StaticAnalyzer(request):
    try:
        #Input validation
        type=request.args['type'] #type of input .apk, eclipse or studio file; to be implemented later
        hash_name=request.args['apk']
        fName=base64.b64decode(hash_name)
        if ((request.args['name'].endswith('.apk') or request.args['name'].endswith('.zip')) and ((type=='zip') or (type=='apk'))):
            directory=settings.BASE_DIR        #BASE DIR
            hash_name=request.args['apk']  #MD5
            app_name=base64.b64decode(hash_name) #APP ORGINAL NAME
            app_directory=os.path.join(directory,'uploads/') #APP DIRECTORY
            #TOOLS_DIR=os.path.join(DIR, 'StaticAnalyzer/tools/')  #TOOLS DIR
            print "[INFO] Starting Analysis on : "+app_name
            #RESCAN= str(request.GET.get('rescan', 0))
            if type=='apk':
                #Check if in DB
                DB=StaticAnalyzerAndroid.objects.filter(MD5=hash_name)
                if DB.exists() and RESCAN=='0':
                    print "\n[INFO] Analysis is already Done. Fetching data from the DB..."
                    context = {
                    #'title' : DB[0].TITLE,
                    'name' : DB[0].APP_NAME,
                    'size' : DB[0].SIZE,
                    'md5': DB[0].MD5,
                    'sha1' : DB[0].SHA1,
                    'sha256' : DB[0].SHA256,
                    """'packagename' : DB[0].PACKAGENAME,
                    'mainactivity' : DB[0].MAINACTIVITY,
                    'targetsdk' : DB[0].TARGET_SDK,
                    'maxsdk' : DB[0].MAX_SDK,
                    'minsdk' : DB[0].MIN_SDK,
                    'androvername' : DB[0].ANDROVERNAME,
                    'androver': DB[0].ANDROVER,
                    'manifest': DB[0].MANIFEST_ANAL,
                    'permissions' : DB[0].PERMISSIONS,
                    'files' : python_list(DB[0].FILES),
                    'certz' : DB[0].CERTZ,
                    'activities' : python_list(DB[0].ACTIVITIES),
                    'receivers' : python_list(DB[0].RECEIVERS),
                    'providers' : python_list(DB[0].PROVIDERS),
                    'services' : python_list(DB[0].SERVICES),
                    'libraries' : python_list(DB[0].LIBRARIES),
                    'act_count' : DB[0].CNT_ACT,
                    'prov_count' : DB[0].CNT_PRO,
                    'serv_count' : DB[0].CNT_SER,
                    'bro_count' : DB[0].CNT_BRO,
                    'certinfo': DB[0].CERT_INFO,
                    'native' : DB[0].NATIVE,
                    'dynamic' : DB[0].DYNAMIC,
                    'reflection' : DB[0].REFLECT,
                    'crypto': DB[0].CRYPTO,
                    'obfus': DB[0].OBFUS,
                    'api': DB[0].API,
                    'dang': DB[0].DANG,
                    'urls': DB[0].URLS,
                    'emails': DB[0].EMAILS,
                    'strings': python_list(DB[0].STRINGS),
                    'zipped' : DB[0].ZIPPED,
                    'mani': DB[0].MANI"""
                    }
                else:
                    app_file=hash_name + '.apk'        #NEW FILENAME
                    app_path=app_dir+app_file    #APP PATH
                    #ANALYSIS BEGINS
                    size_apk=str(FileSize(app_path)) + 'MB'   #FILE SIZE
                    SHA1, SHA256= HashGen(app_path)       #SHA1 & SHA256 HASHES
                    file_namelist=Unzip(app_path,app_dir)
                    CERTZ = GetHardcodedCert(file_namelist)
                    print "[INFO] APK Extracted"
                    parsed_xml= GetManifest(app_dir) #Manifest XML
                    """MANI='../ManifestView/?md5='+MD5+'&type=apk&bin=1'
                    SERVICES,ACTIVITIES,RECEIVERS,PROVIDERS,LIBRARIES,PERM,PACKAGENAME,MAINACTIVITY,MIN_SDK,MAX_SDK,TARGET_SDK,ANDROVER,ANDROVERNAME=ManifestData(PARSEDXML,APP_DIR)
                    MANIFEST_ANAL,EXPORTED_ACT=ManifestAnalysis(PARSEDXML,MAINACTIVITY)
                    PERMISSIONS=FormatPermissions(PERM)
                    CNT_ACT =len(ACTIVITIES)
                    CNT_PRO =len(PROVIDERS)
                    CNT_SER =len(SERVICES)
                    CNT_BRO = len(RECEIVERS)
        
                    CERT_INFO=CertInfo(APP_DIR,TOOLS_DIR)
                    Dex2Jar(APP_DIR,TOOLS_DIR)
                    Dex2Smali(APP_DIR,TOOLS_DIR)
                    Jar2Java(APP_DIR,TOOLS_DIR)
        
                    API,DANG,URLS,EMAILS,CRYPTO,OBFUS,REFLECT,DYNAMIC,NATIVE=CodeAnalysis(APP_DIR,MD5,PERMISSIONS,"apk")
                    print "\n[INFO] Generating Java and Smali Downloads"
                    GenDownloads(APP_DIR,MD5)
                    STRINGS=Strings(APP_FILE,APP_DIR,TOOLS_DIR)
                    ZIPPED='&type=apk'"""
    
                    print "\n[INFO] Connecting to Database"
                    try:
                        #SAVE TO DB
                        """if RESCAN=='1':
                            print "\n[INFO] Updating Database..."
                            StaticAnalyzerAndroid.objects.filter(MD5=MD5).update(TITLE = 'Static Analysis',
                            APP_NAME = APP_NAME,
                            SIZE = SIZE,
                            MD5= MD5,
                            SHA1 = SHA1,
                            SHA256 = SHA256,
                            PACKAGENAME = PACKAGENAME,
                            MAINACTIVITY= MAINACTIVITY,
                            TARGET_SDK = TARGET_SDK,
                            MAX_SDK = MAX_SDK,
                            MIN_SDK = MIN_SDK,
                            ANDROVERNAME = ANDROVERNAME,
                            ANDROVER= ANDROVER,
                            MANIFEST_ANAL= MANIFEST_ANAL,
                            PERMISSIONS = PERMISSIONS,
                            FILES = FILES,
                            CERTZ = CERTZ,
                            ACTIVITIES = ACTIVITIES,
                            RECEIVERS = RECEIVERS,
                            PROVIDERS = PROVIDERS,
                            SERVICES = SERVICES,
                            LIBRARIES = LIBRARIES,
                            CNT_ACT = CNT_ACT,
                            CNT_PRO = CNT_PRO,
                            CNT_SER = CNT_SER,
                            CNT_BRO = CNT_BRO,
                            CERT_INFO= CERT_INFO,
                            NATIVE = NATIVE,
                            DYNAMIC = DYNAMIC,
                            REFLECT = REFLECT,
                            CRYPTO= CRYPTO,
                            OBFUS= OBFUS,
                            API= API,
                            DANG= DANG,
                            URLS= URLS,
                            EMAILS= EMAILS,
                            STRINGS= STRINGS,
                            ZIPPED= ZIPPED,
                            MANI= MANI,
                            EXPORTED_ACT=EXPORTED_ACT)
                        elif RESCAN=='0':"""
                            print "\n[INFO] Saving to Database"
                            STATIC_DB=StaticAnalyzerAndroid(TITLE = 'Static Analysis',
                            APP_NAME = APP_NAME,
                            SIZE = SIZE,
                            MD5= MD5,
                            SHA1 = SHA1,
                            SHA256 = SHA256,
                            """PACKAGENAME = PACKAGENAME,
                            MAINACTIVITY= MAINACTIVITY,
                            TARGET_SDK = TARGET_SDK,
                            MAX_SDK = MAX_SDK,
                            MIN_SDK = MIN_SDK,
                            ANDROVERNAME = ANDROVERNAME,
                            ANDROVER= ANDROVER,
                            MANIFEST_ANAL= MANIFEST_ANAL,
                            PERMISSIONS = PERMISSIONS,
                            FILES = FILES,
                            CERTZ = CERTZ,
                            ACTIVITIES = ACTIVITIES,
                            RECEIVERS = RECEIVERS,
                            PROVIDERS = PROVIDERS,
                            SERVICES = SERVICES,
                            LIBRARIES = LIBRARIES,
                            CNT_ACT = CNT_ACT,
                            CNT_PRO = CNT_PRO,
                            CNT_SER = CNT_SER,
                            CNT_BRO = CNT_BRO,
                            CERT_INFO= CERT_INFO,
                            NATIVE = NATIVE,
                            DYNAMIC = DYNAMIC,
                            REFLECT = REFLECT,
                            CRYPTO= CRYPTO,
                            OBFUS= OBFUS,
                            API= API,
                            DANG= DANG,
                            URLS= URLS,
                            EMAILS= EMAILS,
                            STRINGS= STRINGS,
                            ZIPPED= ZIPPED,
                            MANI= MANI,
                            EXPORTED_ACT=EXPORTED_ACT""")
                            STATIC_DB.save()
                    except Exception as e:
                        print "\n[ERROR] Saving to Database Failed - "+str(e)
                        pass
                    context = {
                    'title' : 'Static Analysis',
                    'name' : APP_NAME,
                    'size' : SIZE,
                    'md5': MD5,
                    'sha1' : SHA1,
                    'sha256' : SHA256,
                    """'packagename' : PACKAGENAME,
                    'mainactivity' : MAINACTIVITY,
                    'targetsdk' : TARGET_SDK,
                    'maxsdk' : MAX_SDK,
                    'minsdk' : MIN_SDK,
                    'androvername' : ANDROVERNAME,
                    'androver': ANDROVER,
                    'manifest': MANIFEST_ANAL,
                    'permissions' : PERMISSIONS,
                    'files' : FILES,
                    'certz' : CERTZ,
                    'activities' : ACTIVITIES,
                    'receivers' : RECEIVERS,
                    'providers' : PROVIDERS,
                    'services' : SERVICES,
                    'libraries' : LIBRARIES,
                    'act_count' : CNT_ACT,
                    'prov_count' : CNT_PRO,
                    'serv_count' : CNT_SER,
                    'bro_count' : CNT_BRO,
                    'certinfo': CERT_INFO,
                    'native' : NATIVE,
                    'dynamic' : DYNAMIC,
                    'reflection' : REFLECT,
                    'crypto': CRYPTO,
                    'obfus': OBFUS,
                    'api': API,
                    'dang': DANG,
                    'urls': URLS,
                    'emails': EMAILS,
                    'strings': STRINGS,
                    'zipped' : ZIPPED,
                    'mani': MANI"""
                    }
                template="static_analysis.html"
                return render_template(request,template,context)
            elif TYP=='zip':
                #Check if in DB
                DB=StaticAnalyzerAndroid.objects.filter(MD5=MD5)
                if DB.exists() and RESCAN=='0':
                    print "\n[INFO] Analysis is already Done. Fetching data from the DB..."
                    context = {
                    #'title' : DB[0].TITLE,
                    'name' : DB[0].APP_NAME,
                    'size' : DB[0].SIZE,
                    'md5': DB[0].MD5,
                    'sha1' : DB[0].SHA1,
                    'sha256' : DB[0].SHA256,
                    """'packagename' : DB[0].PACKAGENAME,
                    'mainactivity' : DB[0].MAINACTIVITY,
                    'targetsdk' : DB[0].TARGET_SDK,
                    'maxsdk' : DB[0].MAX_SDK,
                    'minsdk' : DB[0].MIN_SDK,
                    'androvername' : DB[0].ANDROVERNAME,
                    'androver': DB[0].ANDROVER,
                    'manifest': DB[0].MANIFEST_ANAL,
                    'permissions' : DB[0].PERMISSIONS,
                    'files' : python_list(DB[0].FILES),
                    'certz' : DB[0].CERTZ,
                    'activities' : python_list(DB[0].ACTIVITIES),
                    'receivers' : python_list(DB[0].RECEIVERS),
                    'providers' : python_list(DB[0].PROVIDERS),
                    'services' : python_list(DB[0].SERVICES),
                    'libraries' : python_list(DB[0].LIBRARIES),
                    'act_count' : DB[0].CNT_ACT,
                    'prov_count' : DB[0].CNT_PRO,
                    'serv_count' : DB[0].CNT_SER,
                    'bro_count' : DB[0].CNT_BRO,
                    'native' : DB[0].NATIVE,
                    'dynamic' : DB[0].DYNAMIC,
                    'reflection' : DB[0].REFLECT,
                    'crypto': DB[0].CRYPTO,
                    'obfus': DB[0].OBFUS,
                    'api': DB[0].API,
                    'dang': DB[0].DANG,
                    'urls': DB[0].URLS,
                    'emails': DB[0].EMAILS,
                    'mani': DB[0].MANI"""
                    }
                else:
                    APP_FILE=MD5 + '.zip'        #NEW FILENAME
                    APP_PATH=APP_DIR+APP_FILE    #APP PATH
                    print "[INFO] Extracting ZIP"
                    FILES = Unzip(APP_PATH,APP_DIR)
                    CERTZ = GetHardcodedCert(FILES)
                    #Check if Valid Directory Structure and get ZIP Type
                    pro_type,Valid=ValidAndroidZip(APP_DIR)
                    print "[INFO] ZIP Type - " + pro_type
                    if Valid and (pro_type=='eclipse' or pro_type=='studio'):
                        #ANALYSIS BEGINS
                        SIZE=str(FileSize(APP_PATH)) + 'MB'   #FILE SIZE
                        SHA1,SHA256= HashGen(APP_PATH)        #SHA1 & SHA256 HASHES
                        PARSEDXML= GetManifest(APP_DIR,TOOLS_DIR,pro_type,False)   #Manifest XML
                        MANI='../ManifestView/?md5='+MD5+'&type='+pro_type+'&bin=0'
                        SERVICES,ACTIVITIES,RECEIVERS,PROVIDERS,LIBRARIES,PERM,PACKAGENAME,MAINACTIVITY,MIN_SDK,MAX_SDK,TARGET_SDK,ANDROVER,ANDROVERNAME=ManifestData(PARSEDXML,APP_DIR)
                        MANIFEST_ANAL,EXPORTED_ACT=ManifestAnalysis(PARSEDXML,MAINACTIVITY)
                        PERMISSIONS=FormatPermissions(PERM)
                        CNT_ACT =len(ACTIVITIES)
                        CNT_PRO =len(PROVIDERS)
                        CNT_SER =len(SERVICES)
                        CNT_BRO = len(RECEIVERS)
                        API,DANG,URLS,EMAILS,CRYPTO,OBFUS,REFLECT,DYNAMIC,NATIVE=CodeAnalysis(APP_DIR,MD5,PERMISSIONS,pro_type)
                        print "\n[INFO] Connecting to Database"
                        try:
                            #SAVE TO DB
                            if RESCAN=='1':
                                print "\n[INFO] Updating Database..."
                                StaticAnalyzerAndroid.objects.filter(MD5=MD5).update(TITLE = 'Static Analysis',
                                APP_NAME = APP_NAME,
                                SIZE = SIZE,
                                MD5= MD5,
                                SHA1 = SHA1,
                                SHA256 = SHA256,
                                """PACKAGENAME = PACKAGENAME,
                                MAINACTIVITY= MAINACTIVITY,
                                TARGET_SDK = TARGET_SDK,
                                MAX_SDK = MAX_SDK,
                                MIN_SDK = MIN_SDK,
                                ANDROVERNAME = ANDROVERNAME,
                                ANDROVER= ANDROVER,
                                MANIFEST_ANAL= MANIFEST_ANAL,
                                PERMISSIONS = PERMISSIONS,
                                FILES = FILES,
                                CERTZ = CERTZ,
                                ACTIVITIES = ACTIVITIES,
                                RECEIVERS = RECEIVERS,
                                PROVIDERS = PROVIDERS,
                                SERVICES = SERVICES,
                                LIBRARIES = LIBRARIES,
                                CNT_ACT = CNT_ACT,
                                CNT_PRO = CNT_PRO,
                                CNT_SER = CNT_SER,
                                CNT_BRO = CNT_BRO,
                                CERT_INFO= "",
                                NATIVE = NATIVE,
                                DYNAMIC = DYNAMIC,
                                REFLECT = REFLECT,
                                CRYPTO= CRYPTO,
                                OBFUS= OBFUS,
                                API= API,
                                DANG= DANG,
                                URLS= URLS,
                                EMAILS= EMAILS,
                                STRINGS= "",
                                ZIPPED= "",
                                MANI= MANI,
                                EXPORTED_ACT=EXPORTED_ACT""")
                            elif RESCAN=='0':
                                print "\n[INFO] Saving to Database"
                                STATIC_DB=StaticAnalyzerAndroid(TITLE = 'Static Analysis',
                                APP_NAME = APP_NAME,
                                SIZE = SIZE,
                                MD5= MD5,
                                SHA1 = SHA1,
                                SHA256 = SHA256,
                                """PACKAGENAME = PACKAGENAME,
                                MAINACTIVITY= MAINACTIVITY,
                                TARGET_SDK = TARGET_SDK,
                                MAX_SDK = MAX_SDK,
                                MIN_SDK = MIN_SDK,
                                ANDROVERNAME = ANDROVERNAME,
                                ANDROVER= ANDROVER,
                                MANIFEST_ANAL= MANIFEST_ANAL,
                                PERMISSIONS = PERMISSIONS,
                                FILES = FILES,
                                CERTZ = CERTZ,
                                ACTIVITIES = ACTIVITIES,
                                RECEIVERS = RECEIVERS,
                                PROVIDERS = PROVIDERS,
                                SERVICES = SERVICES,
                                LIBRARIES = LIBRARIES,
                                CNT_ACT = CNT_ACT,
                                CNT_PRO = CNT_PRO,
                                CNT_SER = CNT_SER,
                                CNT_BRO = CNT_BRO,
                                CERT_INFO= "",
                                NATIVE = NATIVE,
                                DYNAMIC = DYNAMIC,
                                REFLECT = REFLECT,
                                CRYPTO= CRYPTO,
                                OBFUS= OBFUS,
                                API= API,
                                DANG= DANG,
                                URLS= URLS,
                                EMAILS= EMAILS,
                                STRINGS= "",
                                ZIPPED= "",
                                MANI= MANI,
                                EXPORTED_ACT=EXPORTED_ACT""")
                                STATIC_DB.save()
                        except Exception as e:
                            print "\n[ERROR] Saving to Database Failed - "+str(e)
                            pass
                        context = {
                        'title' : 'Static Analysis',
                        'name' : APP_NAME,
                        'size' : SIZE,
                        'md5': MD5,
                        'sha1' : SHA1,
                        'sha256' : SHA256,
                        """'packagename' : PACKAGENAME,
                        'mainactivity' : MAINACTIVITY,
                        'targetsdk' : TARGET_SDK,
                        'maxsdk' : MAX_SDK,
                        'minsdk' : MIN_SDK,
                        'androvername' : ANDROVERNAME,
                        'androver': ANDROVER,
                        'manifest': MANIFEST_ANAL,
                        'permissions' : PERMISSIONS,
                        'files' : FILES,
                        'certz' : CERTZ,
                        'activities' : ACTIVITIES,
                        'receivers' : RECEIVERS,
                        'providers' : PROVIDERS,
                        'services' : SERVICES,
                        'libraries' : LIBRARIES,
                        'act_count' : CNT_ACT,
                        'prov_count' : CNT_PRO,
                        'serv_count' : CNT_SER,
                        'bro_count' : CNT_BRO,
                        'native' : NATIVE,
                        'dynamic' : DYNAMIC,
                        'reflection' : REFLECT,
                        'crypto': CRYPTO,
                        'obfus': OBFUS,
                        'api': API,
                        'dang': DANG,
                        'urls': URLS,
                        'emails': EMAILS,
                        'mani': MANI,"""
                        }
                    elif Valid and pro_type=='ios':
                        print "[INFO] Redirecting to iOS Source Code Analyzer"
                        return HttpResponseRedirect('/StaticAnalyzer_iOS/?name='+APP_NAME+'&type=ios&checksum='+MD5)
                    else:
                        return HttpResponseRedirect('/ZIP_FORMAT/')
                template="static_analysis_zip.html"
                return render(request,template,context)
            else:
                print "\n[ERROR] Only APK,IPA and Zipped Android/iOS Source code supported now!"  
        else:
            return HttpResponseRedirect('/error/')

    except Exception as e:
        context = {
        'title' : 'Error',
        'exp' : e.message,
        'doc' : e.__doc__
        }
        template="error.html"
        return render(request,template,context)

def GetHardcodedCert(files):
    print "[INFO] Getting Hardcoded Certificates"
    certz=''
    for f in files:
        ext=f.split('.')[-1]
        if re.search("cer|pem|cert|crt|pub|key|pfx|p12", ext):
            certz+=escape(f) + "</br>"
    if len(certz)>1:
        certz="<tr><td>Certificate/Key Files Hardcoded inside the App.</td><td>"+certz+"</td><tr>"
    return certz
    return re.sub(RE_XML_ILLEGAL, "?", dat)

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