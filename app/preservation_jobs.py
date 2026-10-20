"""Durable, single-flight preservation requests. No command execution or approval changes."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
import time

IDENTIFIER = re.compile(r'^[A-Za-z0-9_-]{1,100}$')
WORKSPACE = re.compile(r'^[a-f0-9]{32}$')
ACTIVE = {'queued', 'running'}

class PreservationJobs:
    def __init__(self, root):
        self.root = Path(root)
        for p in (self.root, *self.root.parents):
            if p.is_symlink(): raise ValueError('Preservation registry link refused')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.records = {}
        self.threads = {}
        for path in sorted(self.root.glob('*.json')):
            record = self._read(path)
            if path.name != record['preservationTaskId'] + '.json':
                raise ValueError('Preservation record identity mismatch')
            if record['status'] in ACTIVE:
                record.update(status='unknown', preserved=False, finishedAt=time.time(),
                              errorCode='service_restarted_no_automatic_replay')
                self._save(record)
            self.records[record['preservationTaskId']] = record

    def _read(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
                raise ValueError('Invalid preservation record')
            with os.fdopen(os.dup(fd), 'r') as stream: record = json.load(stream)
        finally: os.close(fd)
        if (not isinstance(record, dict) or not IDENTIFIER.fullmatch(record.get('preservationTaskId', ''))
                or not WORKSPACE.fullmatch(record.get('workspaceId', ''))
                or record.get('status') not in ACTIVE | {'succeeded', 'failed', 'unknown'}):
            raise ValueError('Invalid preservation record identity')
        return record

    def _save(self, record):
        raw = (json.dumps(record, sort_keys=True, ensure_ascii=False) + '\n').encode()
        fd, temporary = tempfile.mkstemp(dir=self.root, prefix='.preserve-')
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fchmod(stream.fileno(), 0o600); os.fsync(stream.fileno())
            os.replace(temporary, self.root / (record['preservationTaskId'] + '.json'))
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)

    def _public(self, record):
        allowed = ('preservationTaskId', 'requestId', 'workspaceId', 'profile', 'status',
                   'preserved', 'createdAt', 'finishedAt', 'stage', 'filesCopied',
                   'directoriesCopied', 'bytesCopied', 'errorCode')
        result = {k: record[k] for k in allowed if k in record}
        if record['status'] == 'succeeded': result.update(record['result'])
        result['pollWith'] = 'dev_execution_preserve using the same workspaceId and requestId'
        return result

    def busy(self, workspace_id):
        with self.lock:
            return any(r['workspaceId'] == workspace_id and r['status'] in ACTIVE
                       for r in self.records.values())

    def submit(self, workspace_id, profile, request_id, work, allow_new=True):
        if (not isinstance(workspace_id, str) or not WORKSPACE.fullmatch(workspace_id)
                or profile != 'autonomous-development' or not isinstance(request_id, str)
                or not IDENTIFIER.fullmatch(request_id)):
            raise ValueError('Invalid preservation request identity')
        task_id = 'preserve-' + hashlib.sha256(
            json.dumps([profile, workspace_id, request_id], separators=(',', ':')).encode()).hexdigest()[:32]
        with self.lock:
            if task_id in self.records: return self._public(self.records[task_id])
            if not allow_new: raise ValueError('Closed workspace only permits existing request queries')
            if self.busy(workspace_id):
                raise ValueError('Preservation already pending; query the original requestId')
            descriptor = os.open(self.root / ('workspace-' + workspace_id + '.lock'),
                                 os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode) or os.fstat(descriptor).st_nlink != 1:
                    raise ValueError('Invalid preservation lock')
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                record = {'preservationTaskId': task_id, 'requestId': request_id,
                          'workspaceId': workspace_id, 'profile': profile, 'status': 'queued',
                          'preserved': False, 'createdAt': time.time(), 'stage': 'queued',
                          'filesCopied': 0, 'directoriesCopied': 0, 'bytesCopied': 0}
                self._save(record); self.records[task_id] = record
                thread = threading.Thread(target=self._worker, args=(task_id, descriptor, work), daemon=True)
                self.threads[task_id] = thread
                thread.start()
            except Exception:
                os.close(descriptor)
                if task_id in self.records and self.records[task_id]['status'] == 'queued':
                    self.records[task_id].update(status='unknown', errorCode='worker_start_failed',
                                                 finishedAt=time.time())
                    self._save(self.records[task_id])
                raise
        # Preserve backwards compatibility for tiny requests, without holding up large copies.
        thread.join(0.2)
        with self.lock: return self._public(self.records[task_id])

    def _worker(self, task_id, descriptor, work):
        last_save = [0.0]
        def progress(stage, files=0, directories=0, size=0):
            with self.lock:
                record = self.records[task_id]
                record.update(stage=stage, filesCopied=files, directoriesCopied=directories, bytesCopied=size)
                now = time.monotonic()
                if now - last_save[0] >= 0.5:
                    self._save(record); last_save[0] = now
        try:
            with self.lock:
                self.records[task_id]['status'] = 'running'; self._save(self.records[task_id])
            result = work(task_id.removeprefix('preserve-'), progress)
            if not isinstance(result, dict) or result.get('preserved') is not True:
                raise ValueError('Preservation result was not successful')
            safe_result = {k: result[k] for k in ('workspaceId', 'preservationId', 'treeHash',
                           'files', 'directories', 'preserved') if k in result}
            with self.lock:
                self.records[task_id].update(status='succeeded', preserved=True, result=safe_result,
                                             stage='complete', finishedAt=time.time())
                self._save(self.records[task_id])
        except Exception:
            with self.lock:
                record = self.records[task_id]
                record.pop('result', None)
                record.update(status='failed', preserved=False, errorCode='preservation_failed_original_retained',
                              finishedAt=time.time())
                self._save(record)
        finally:
            os.close(descriptor)
