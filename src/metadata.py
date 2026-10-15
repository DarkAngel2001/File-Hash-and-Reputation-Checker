import mimetypes
from pathlib import Path
from datetime import datetime


def format_size(size_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def get_file_metadata(file_path: Path) -> dict:
    stat = file_path.stat()
    
    mime_type, _ = mimetypes.guess_type(str(file_path))
    if not mime_type:
        mime_type = "application/octet-stream"

    return {
        "filename": file_path.name,
        "absolute_path": str(file_path.resolve()),
        "size_bytes": stat.st_size,
        "size_human": format_size(stat.st_size),
        "mime_type": mime_type,
        "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
        "permissions": oct(stat.st_mode)[-3:],
    }