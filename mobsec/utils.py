import os

ALLOWED_EXTENSIONS = set(['ipa', 'zip', 'apk'])


def get_file_paths(directory):
    file_paths = []
    for dirpath, _, filenames in os.walk(directory):
        for file in filenames:
            file_paths.append(os.path.abspath(os.path.join(dirpath, file)))

    return file_paths


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS
