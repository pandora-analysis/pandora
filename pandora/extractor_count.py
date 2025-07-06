import zipfile
import tarfile
import sys

def count_zip_entries(path):
    with zipfile.ZipFile(path,"r") as zf:
        return len(zf.infolist())
    
def count_tar_entries(path):
    with tarfile.open(path,"r") as tf:
        return len([m for m in tf.getmembers() if m.isfile()])
    

if __name__ == "__main__":
    path = sys.argv[1]
    if path.endswith(".zip"):
        print("Zip file count", count_zip_entries(path))
    elif path.endswith(".tar") or path.endswith(".tar.gz") or path.endswith(".tgz"):
        print("TAR file count:", count_tar_entries(path))
    else:
        print("Unsupported file type")
    