import os
import re

class ObjectStorageError(Exception):
    def __init__(self, message):
        self.message = message

class ObjectStorageInterface:
    def __init__(self):
        pass

    def ensure_bucket_exists(self, bucket_name):
        raise ObjectStorageError("Method is abstract")

    def get(self, bucket_name, object_name):
        raise ObjectStorageError("Method is abstract")

    def put(self, bucket_name, object_name, object_body):
        raise ObjectStorageError("Method is abstract")

def sanitize(name):
    return re.sub(r"[^A-Za-z0-9_-]+", "_", name)

class FileSystemObjectStorage(ObjectStorageInterface):
    def __init__(self, basedir):
        self.basedir = basedir

    def ensure_bucket_exists(self, bucket_name):
        bucket = os.path.join(self.basedir, sanitize(bucket_name))
        try:
            if os.path.exists(bucket):
                if os.path.isdir(bucket):
                    return
                else:
                    raise ObjectStorageError("Path {} already exists but is not a directory".format(bucket))
            else:
                os.mkdir(bucket)
        except OSError as e:
            raise ObjectStorageError("OS error: {}".format(e))

    def get(self, bucket_name, object_name):
        try:
            path = os.path.join(self.basedir, sanitize(bucket_name), sanitize(object_name))
            if os.path.exists(path):
                if os.path.isfile(path):
                    with open(path, "rb") as f:
                        return f.read()
                else:
                    raise ObjectStorageError("Object {} is not a file on the disk".format(object_name))
            else:
                raise ObjectStorageError("Bucket {} does not contain object {}".format(bucket_name, object_name))
        except OSError as e:
            raise ObjectStorageError("OS error: {}".format(e))
        except IOError as e:
            raise ObjectStorageError("File I/O error: {}".format(e))
        
    def put(self, bucket_name, object_name, object_body):
        try:
            path = os.path.join(self.basedir, sanitize(bucket_name), sanitize(object_name))
            with open(path, "wb") as f:
                f.write(object_body)
        except OSError as e:
            raise ObjectStorageError("OS error: {}".format(e))
        except IOError as e:
            raise ObjectStorageError("File I/O error: {}".format(e))
