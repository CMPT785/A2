import os
from utils.storage_interface import Storage

class FileStorage(Storage):
    """
    This class is used to store files.
    """
    def __init__(self, storage_directory='/app/object_storage'):
        # Should move to an S3 bucket in future to store the data so it's more scalable
        self.storage_directory = storage_directory
        try:
            os.mkdir(storage_directory, exist_ok=True)
        except:
            None
    
    
    def store(self, filename, contents):
        # Sanitize filename to prevent path traversal
        safe_filename = os.path.basename(filename)
        
        if len(contents) > 10 * 1024 * 1024:  # 10 MB
            raise ValueError("File too large")
        os.makedirs(self.storage_directory, exist_ok=True)
        file_path = os.path.normpath(os.path.join(self.storage_directory, safe_filename))
        if not file_path.startswith(os.path.abspath(self.storage_directory)):
            raise ValueError("Invalid file path")
        with open(file_path, 'wb') as fp:
            fp.write(contents)

    def get(self, filename):
        # Sanitize filename to prevent path traversal
        safe_filename = os.path.basename(filename)
        file_path = os.path.normpath(os.path.join(self.storage_directory, safe_filename))

        # Prevent directory traversal
        if not file_path.startswith(os.path.abspath(self.storage_directory)):
            raise ValueError("Invalid file path")
            
        try:
            with open(file_path, 'rb') as fp:
                contents = fp.read()
            return contents
        except FileNotFoundError:
            return None
    
    def delete(self, filename):
        # Sanitize filename to prevent path traversal
        safe_filename = os.path.basename(filename)
        file_path = os.path.normpath(os.path.join(self.storage_directory, safe_filename))
        # Prevent directory traversal
        if not file_path.startswith(os.path.abspath(self.storage_directory)):
            raise ValueError("Invalid file path")
            
        try:
            os.remove(file_path)
            return True
        except Exception:
            return False