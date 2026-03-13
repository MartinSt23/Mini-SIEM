from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, parser, on_event):
            self.parser = parser
            self.on_event = on_event
            self._offset = {}
            self._last_lines = set()
    
    def on_modified(self, event):
        if not event.src_path.endswith(".log"):
            return
        path = event.src_path
        offset = self._offset.get(path, 0)
        with open(path, "r") as f:
            f.seek(offset)
            for line in f:
                line = line.strip()
                if line and line not in self._last_lines:
                    self._last_lines.add(line)
                    parsed = self.parser.parse(line)
                    if parsed:
                        self.on_event(parsed)
            self._offset[path] = f.tell()
            
def watch(path: str, parser, on_event):
    handler = LogFileHandler(parser, on_event)
    observer = Observer()
    observer.schedule(handler, path=path, recursive=False)
    observer.start()
    return observer