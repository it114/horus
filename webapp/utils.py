import httplib
import mimetypes
import contextlib
import io
from contextlib import contextmanager


ALLOWED_EXTENSIONS = set(['ipa', 'zip', 'apk'])


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@contextmanager
def stdout_redirector(stream):
    old_stdout = sys.stdout
    sys.stdout = stream
    try:
        yield
    finally:
        sys.stdout = old_stdout
