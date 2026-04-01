import traceback
from analyzer import parse_eml
import io
from werkzeug.datastructures import FileStorage

try:
    with open('test.eml', 'rb') as f:
        stream = io.BytesIO(f.read())
        file_storage = FileStorage(stream=stream, filename="test.eml")
        res = parse_eml(file_storage.stream)
        print("Success:", res)
except Exception as e:
    print("Error:", e)
    traceback.print_exc()
